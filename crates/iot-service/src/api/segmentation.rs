//! Segmentation APIs (ZTE-IOT sections 70–79 segmentation and device
//! policy, 83 Policy Simulation, 84 Policy Activation/Rollback, 85
//! Exception Workflow, 102 Segmentation UI, 108 Policy APIs, 129
//! Segmentation Certification, 131 Fleet/Site Rollout; Volume 2
//! "Segmentation Policy"; AE-IOT-0006 recommendations, AE-IOT-0012
//! conduits).
//!
//! Segmentation rules live in the platform (`iot.segmentation` policy
//! sets, change workflow, approval, activation). This service owns the
//! objects they reference (zones, device groups, exceptions) and offers:
//!
//! * `POST /api/v1/segmentation/decide` — decide one flow with the active policy;
//! * `POST /api/v1/segmentation/simulate` — replay observed flows (last
//!   `hours`) against the active policy or a draft rule set;
//! * `GET /api/v1/segmentation/recommendations?group_id=` — allow-list rule
//!   set from baselines of high-confidence members;
//! * `POST /api/v1/segmentation/assign-preview` — group/zone assignment of a device;
//! * `GET /api/v1/segmentation/conduits` — zone-to-zone communication;
//! * `GET /api/v1/segmentation/snapshot`, `GET /api/v1/config-revisions`,
//!   `POST /api/v1/config-revisions/{revision}/rollback`;
//! * `POST /api/v1/exceptions` (+ `/{id}/approve|deny|revoke`) — temporary
//!   exceptions with approval (platform approval inbox when configured);
//! * `POST /api/v1/rollouts/{id}/start|advance|rollback` — staged changes of
//!   zone enforcement modes.

use super::common::{body_str, pre, q_uuid};
use super::ingest::{build_snapshot, record_revision};
use crate::pipeline;
use crate::state::{AppState, ACTIVATE, CREATE, READ, UPDATE};
use aether_core::policy::compile::{compile, Target};
use aether_core::policy::eval::PreparedPolicy;
use aether_core::policy::RuleSet;
use aether_kit::audit::{self, Entry};
use aether_kit::{events, ActorType, ApiError, ApiResult, Ctx, Envelope};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use iot_core::policy::{DeviceCtx, FlowCtx};
use iot_core::segmentation::{self, DeviceFacts, Exception};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/segmentation/decide", post(decide))
        .route("/api/v1/segmentation/simulate", post(simulate))
        .route("/api/v1/segmentation/recommendations", get(recommendations))
        .route("/api/v1/segmentation/assign-preview", post(assign_preview))
        .route("/api/v1/segmentation/conduits", get(conduits))
        .route("/api/v1/segmentation/snapshot", get(snapshot))
        .route("/api/v1/config-revisions", get(revisions))
        .route("/api/v1/config-revisions/{revision}/rollback", post(rollback))
        .route("/api/v1/exceptions", post(create_exception))
        .route("/api/v1/exceptions/{id}/{action}", post(exception_action))
        .route("/api/v1/rollouts/{id}/{action}", post(rollout_action))
}

/// Device context of an asset for policy evaluation.
pub async fn device_ctx(tx: &mut aether_kit::db::Tx, id: Uuid) -> ApiResult<DeviceCtx> {
    let r: Option<(Value,)> = sqlx::query_as(
        "SELECT jsonb_build_object('id', id, 'groups', group_ids, 'zone', zone_id, 'site', site_id, 'device_type', device_type, 'category', category, 'risk_level', risk_level,
                'tier', tier, 'quarantined', quarantined, 'ip', ip, 'evaluated_at', risk_evaluated_at) FROM assets WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let v = r.ok_or_else(|| ApiError::not_found("asset"))?.0;
    Ok(device_ctx_of(&v))
}

pub fn device_ctx_of(v: &Value) -> DeviceCtx {
    let s = |k: &str| v[k].as_str().map(String::from);
    let ty = s("device_type");
    DeviceCtx {
        device_id: s("id"),
        groups: v["groups"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        zone: s("zone"),
        site: s("site"),
        safety_sensitive: ty.as_deref().map(|t| iot_core::taxonomy::get(t).safety_sensitive).unwrap_or(false),
        device_type: ty,
        category: s("category"),
        risk_level: s("risk_level"),
        confidence_tier: s("tier"),
        quarantined: v["quarantined"].as_bool().unwrap_or(false),
        ip: s("ip"),
        evaluated_at: s("evaluated_at").and_then(|t| t.parse().ok()),
    }
}

/// Approved, active exceptions of the tenant.
pub async fn active_exceptions(tx: &mut aether_kit::db::Tx) -> ApiResult<Vec<Exception>> {
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT jsonb_build_object('id', id::text, 'source_device', source_asset_id::text, 'destination_device', destination_asset_id::text, 'source_group', source_group_id::text,
                'destination_group', destination_group_id::text, 'protocol', protocol, 'port', port, 'max_op', max_op, 'starts_at', starts_at, 'expires_at', expires_at)
         FROM exceptions WHERE deleted_at IS NULL AND state = 'approved' AND expires_at > now()",
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().filter_map(|r| serde_json::from_value(r.0).ok()).collect())
}

/// Compile a draft rule set of `iot.segmentation` (validation issues → 422).
pub fn compile_draft(tenant: Uuid, rs: &RuleSet) -> ApiResult<PreparedPolicy> {
    let t = iot_core::policy::types().into_iter().find(|t| t.key == iot_core::policy::SEGMENTATION).ok_or_else(|| ApiError::internal("segmentation type missing"))?;
    if rs.policy_type != t.key {
        return Err(ApiError::field("ruleset.policy_type", "invalid", iot_core::policy::SEGMENTATION));
    }
    let c = compile(&t, rs, Target { tenant_id: tenant, policy_set_id: Uuid::nil(), revision: 0 }).map_err(ApiError::issues)?;
    Ok(PreparedPolicy::new(c))
}

async fn decide(State(st): State<AppState>, ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    if ctx.p.actor_type != ActorType::Service {
        pre(&ctx, READ)?;
    }
    let at: DateTime<Utc> = body["at"].as_str().and_then(|t| t.parse().ok()).unwrap_or_else(Utc::now);
    let mut tx = ctx.tx().await?;
    let mut f: FlowCtx = FlowCtx {
        protocol: body_str(&body, "protocol").map(String::from),
        operation_class: body_str(&body, "operation_class").map(String::from),
        operation: body_str(&body, "operation").map(String::from),
        port: body["port"].as_u64().map(|p| p as u16),
        internet: body["internet"].as_bool().unwrap_or(false),
        at: Some(at),
        ..Default::default()
    };
    for (side, key_id, key_ip) in [("source", "source_asset_id", "source_ip"), ("destination", "destination_asset_id", "destination_ip")] {
        let d = if let Some(id) = body[key_id].as_str().and_then(|s| Uuid::parse_str(s).ok()) {
            device_ctx(&mut tx, id).await?
        } else if let Some(ip) = body[key_ip].as_str() {
            let r: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM assets WHERE ip = $1 AND merged_into IS NULL AND deleted_at IS NULL ORDER BY last_seen DESC LIMIT 1")
                .bind(ip)
                .fetch_optional(&mut *tx)
                .await?;
            match r {
                Some((id,)) => device_ctx(&mut tx, id).await?,
                None => DeviceCtx { ip: Some(ip.to_string()), ..Default::default() },
            }
        } else {
            DeviceCtx::default()
        };
        if side == "source" {
            f.source = d;
        } else {
            f.destination = d;
        }
    }
    let ex = active_exceptions(&mut tx).await?;
    let (zones,) = (pipeline::groups_zones(&mut tx).await?.1,);
    tx.commit().await?;
    let policy = match body.get("ruleset") {
        Some(rs) if !rs.is_null() => {
            Some(std::sync::Arc::new(compile_draft(ctx.tenant(), &serde_json::from_value(rs.clone()).map_err(|e| ApiError::bad_request(format!("invalid ruleset: {e}")))?)?))
        }
        _ => st.segmentation_policy(ctx.tenant()).await,
    };
    let v = segmentation::decide(policy.as_deref(), &ex, &zones, &f, at);
    Ok(Envelope::ok(
        &ctx,
        json!({ "verdict": v, "flow": f, "policy_source": if body.get("ruleset").map(|r| !r.is_null()).unwrap_or(false) { "draft" } else if policy.is_some() { "active" } else { "none" } }),
    ))
}

/// Observed flows of the last `hours` as policy flows (asset to asset).
pub async fn observed_flows(tx: &mut aether_kit::db::Tx, hours: i64, max: i64) -> ApiResult<Vec<FlowCtx>> {
    let rows: Vec<(Value, Value, Option<String>, Option<String>, i32, bool)> = sqlx::query_as(
        "SELECT jsonb_build_object('id', a.id, 'groups', a.group_ids, 'zone', a.zone_id, 'site', a.site_id, 'device_type', a.device_type, 'category', a.category, 'risk_level', a.risk_level, 'tier', a.tier, 'quarantined', a.quarantined, 'ip', a.ip, 'evaluated_at', a.risk_evaluated_at),
                coalesce(jsonb_build_object('id', p.id, 'groups', p.group_ids, 'zone', p.zone_id, 'site', p.site_id, 'device_type', p.device_type, 'category', p.category, 'risk_level', p.risk_level, 'tier', p.tier, 'quarantined', p.quarantined, 'ip', p.ip, 'evaluated_at', p.risk_evaluated_at), jsonb_build_object('ip', f.peer_ip)),
                f.protocol, f.max_op, f.port, f.outbound
         FROM (SELECT asset_id, peer_ip, peer_asset_id, protocol, port, outbound, max(max_op) AS max_op FROM flow_rollups WHERE bucket > now() - make_interval(hours => $1) GROUP BY 1,2,3,4,5,6) f
         JOIN assets a ON a.id = f.asset_id LEFT JOIN assets p ON p.id = f.peer_asset_id
         WHERE f.outbound LIMIT $2",
    )
    .bind(hours as i32)
    .bind(max)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(a, p, proto, op, port, _)| {
            let src = device_ctx_of(&a);
            let mut dst = device_ctx_of(&p);
            if dst.device_id.is_none() {
                dst.ip = p["ip"].as_str().map(String::from);
            }
            let internet = dst.ip.as_deref().and_then(|i| i.parse::<std::net::IpAddr>().ok()).map(|i| iot_core::risk::is_public(&i)).unwrap_or(false);
            FlowCtx { source: src, destination: dst, protocol: proto, operation_class: op, operation: None, port: Some(port as u16), internet, at: None }
        })
        .collect())
}

async fn simulate(State(st): State<AppState>, ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let hours = body["hours"].as_i64().unwrap_or(24).clamp(1, 24 * 30);
    let policy = match body.get("ruleset") {
        Some(rs) if !rs.is_null() => Some(compile_draft(ctx.tenant(), &serde_json::from_value(rs.clone()).map_err(|e| ApiError::bad_request(format!("invalid ruleset: {e}")))?)?),
        _ => None,
    };
    let mut tx = ctx.tx().await?;
    let flows = observed_flows(&mut tx, hours, 50_000).await?;
    let ex = active_exceptions(&mut tx).await?;
    tx.commit().await?;
    let started = std::time::Instant::now();
    let sim = match policy {
        Some(p) => segmentation::simulate(&p, &ex, &flows, Utc::now()),
        None => match st.segmentation_policy(ctx.tenant()).await {
            Some(p) => segmentation::simulate(&p, &ex, &flows, Utc::now()),
            None => return Err(ApiError::conflict("no_policy", "no active iot.segmentation policy; pass a draft \"ruleset\"")),
        },
    };
    st.telemetry.observe("simulate", started.elapsed());
    Ok(Envelope::ok(&ctx, json!({ "hours": hours, "simulation": sim })))
}

async fn recommendations(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let g = q_uuid(&q, "group_id")?.ok_or_else(|| ApiError::field("group_id", "required", "device group id"))?;
    let mut tx = ctx.tx().await?;
    let members: Vec<(Uuid, f64, Value)> =
        sqlx::query_as("SELECT a.id, a.confidence, b.data FROM assets a JOIN baselines b ON b.asset_id = a.id WHERE $1 = ANY(a.group_ids) AND a.merged_into IS NULL LIMIT 2000")
            .bind(g)
            .fetch_all(&mut *tx)
            .await?;
    let peers: Vec<(String, Vec<Uuid>)> =
        sqlx::query_as("SELECT ip, group_ids FROM assets WHERE ip IS NOT NULL AND merged_into IS NULL AND deleted_at IS NULL LIMIT 200000").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let bases: Vec<(String, f64, iot_core::baseline::Baseline)> =
        members.into_iter().filter_map(|(id, c, d)| serde_json::from_value(d).ok().map(|b| (id.to_string(), c, b))).collect();
    let refs: Vec<(String, f64, &iot_core::baseline::Baseline)> = bases.iter().map(|(a, c, b)| (a.clone(), *c, b)).collect();
    let peer_groups: BTreeMap<String, Vec<String>> = peers.into_iter().map(|(ip, gs)| (ip, gs.into_iter().map(|x| x.to_string()).collect())).collect();
    let rs = segmentation::recommend(&g.to_string(), &refs, &peer_groups);
    Ok(Envelope::ok(
        &ctx,
        json!({ "group_id": g, "members_considered": refs.iter().filter(|m| m.1 >= 0.9).count(), "members_excluded_low_confidence": refs.iter().filter(|m| m.1 < 0.9).count(), "ruleset": rs }),
    ))
}

async fn assign_preview(ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let facts: DeviceFacts = if let Some(id) = body["asset_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()) {
        let a = super::assets::load(&mut tx, id).await?;
        DeviceFacts {
            id: id.to_string(),
            device_type: a["device_type"].as_str().unwrap_or("unknown").into(),
            category: a["category"].as_str().unwrap_or("unknown").into(),
            vendor: a["vendor"].as_str().map(String::from),
            model: a["model"].as_str().map(String::from),
            site: a["site_id"].as_str().map(String::from),
            tags: a["tags"].as_array().map(|x| x.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
            risk_level: a["risk_level"].as_str().map(String::from),
            confidence: a["confidence"].as_f64().unwrap_or(0.0),
            quarantined: a["quarantined"].as_bool().unwrap_or(false),
            pinned_groups: a["pinned_group_ids"].as_array().map(|x| x.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
        }
    } else {
        serde_json::from_value(body.clone()).map_err(|e| ApiError::bad_request(format!("expected asset_id or device facts: {e}")))?
    };
    let (groups, zones) = pipeline::groups_zones(&mut tx).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, segmentation::assign(&facts, &groups, &zones)))
}

async fn conduits(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let g = super::ops::load_graph(&mut tx, 200_000).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, g.conduits()))
}

async fn snapshot(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let doc = build_snapshot(&mut tx, ctx.tenant(), q_uuid(&q, "site_id")?).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, doc))
}

async fn revisions(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> =
        sqlx::query_as("SELECT jsonb_build_object('revision', revision, 'hash', hash, 'note', note, 'created_by', created_by, 'created_at', created_at, 'active', active) FROM config_revisions ORDER BY revision DESC LIMIT 200")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

/// Restore zone modes/levels and group definitions of an earlier revision.
async fn rollback(State(st): State<AppState>, ctx: Ctx, Path(revision): Path<i64>) -> ApiResult<Envelope> {
    pre(&ctx, ACTIVATE)?;
    let mut tx = ctx.tx().await?;
    let r: Option<(Value,)> = sqlx::query_as("SELECT snapshot FROM config_revisions WHERE revision = $1").bind(revision).fetch_optional(&mut *tx).await?;
    let snap = r.ok_or_else(|| ApiError::not_found("configuration revision"))?.0;
    let mut zones = 0;
    for z in snap["zones"].as_array().cloned().unwrap_or_default() {
        zones += sqlx::query(
            "UPDATE zones SET mode = $2, security_level = $3, safety_critical = $4, version = version + 1, updated_at = now() WHERE id = $1::uuid AND deleted_at IS NULL",
        )
        .bind(z["id"].as_str())
        .bind(z["mode"].as_str())
        .bind(z["security_level"].as_i64().unwrap_or(2) as i32)
        .bind(z["safety_critical"].as_bool().unwrap_or(false))
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    let mut groups = 0;
    for g in snap["groups"].as_array().cloned().unwrap_or_default() {
        groups += sqlx::query("UPDATE device_groups SET match = $2, zone_id = $3::uuid, priority = $4, privileged = $5, min_confidence = $6, version = version + 1, updated_at = now() WHERE id = $1::uuid AND deleted_at IS NULL")
            .bind(g["id"].as_str())
            .bind(&g["matcher"])
            .bind(g["zone"].as_str())
            .bind(g["priority"].as_i64().unwrap_or(0) as i32)
            .bind(g["privileged"].as_bool().unwrap_or(false))
            .bind(g["min_confidence"].as_f64().unwrap_or(0.0))
            .execute(&mut *tx)
            .await?
            .rows_affected();
    }
    audit::record(&mut tx, &ctx, Entry::new("rollback", "config_revision", Some(revision)).reason(format!("{zones} zones, {groups} groups restored"))).await?;
    events::emit_simple(&mut tx, &ctx, "iot_config", "rolled_back", revision, None, json!({ "revision": revision, "zones": zones, "groups": groups })).await?;
    tx.commit().await?;
    st.invalidate(ctx.tenant());
    // Re-assign every asset under the restored groups, then record the new revision.
    let mut tx = ctx.tx().await?;
    let ids: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM assets WHERE merged_into IS NULL AND deleted_at IS NULL AND lifecycle <> 'decommissioned' LIMIT 100000").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &ids.into_iter().map(|i| i.0).collect::<Vec<_>>()).await?;
    let mut tx = ctx.tx().await?;
    let doc = build_snapshot(&mut tx, ctx.tenant(), None).await?;
    let new_rev = record_revision(&mut tx, ctx.tenant(), &doc, &ctx.p.name, &format!("rollback to revision {revision}")).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, json!({ "restored_from": revision, "zones": zones, "groups": groups, "revision": new_rev, "hash": doc["content_hash"] })))
}

async fn create_exception(State(st): State<AppState>, ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, CREATE)?;
    let obj = aether_kit::resource::validate_body(&super::resources::EXCEPTIONS, &body, &aether_kit::resource::Mode::Create)?;
    let parse_t = |k: &str| obj.get(k).and_then(|v| v.as_str()).and_then(|s| s.parse::<DateTime<Utc>>().ok());
    let (starts, expires) = (
        parse_t("starts_at").ok_or_else(|| ApiError::field("starts_at", "required", "RFC 3339"))?,
        parse_t("expires_at").ok_or_else(|| ApiError::field("expires_at", "required", "RFC 3339"))?,
    );
    let u = |k: &str| obj.get(k).and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());
    let e = Exception {
        id: String::new(),
        source_device: u("source_asset_id").map(|x| x.to_string()),
        destination_device: u("destination_asset_id").map(|x| x.to_string()),
        source_group: u("source_group_id").map(|x| x.to_string()),
        destination_group: u("destination_group_id").map(|x| x.to_string()),
        protocol: obj.get("protocol").and_then(|v| v.as_str()).map(String::from),
        port: obj.get("port").and_then(|v| v.as_u64()).map(|p| p as u16),
        max_op: obj.get("max_op").and_then(|v| v.as_str()).and_then(segmentation::op_class),
        starts_at: starts,
        expires_at: expires,
    };
    e.validate(30).map_err(|c| ApiError::field("expires_at", c, "exceptions are specific and at most 30 days"))?;
    if expires <= Utc::now() {
        return Err(ApiError::field("expires_at", "in_past", "must be in the future"));
    }
    let id = Uuid::now_v7();
    let mut tx = ctx.tx().await?;
    for k in ["source_asset_id", "destination_asset_id"] {
        if let Some(a) = u(k) {
            super::assets::load(&mut tx, a).await.map_err(|_| ApiError::field(k, "invalid_reference", "unknown asset"))?;
        }
    }
    let mut ins = obj.clone();
    ins.insert("state".into(), json!("pending_approval"));
    let row = aether_kit::resource::insert(&mut tx, &ctx, &super::resources::EXCEPTIONS, ins, serde_json::Map::from_iter([("id".to_string(), json!(id))])).await?;
    audit::record(&mut tx, &ctx, Entry::new("create", "exception", Some(id)).after(Some(row.clone()))).await?;
    events::emit_simple(&mut tx, &ctx, "exception", "created", id, Some(1), row.clone()).await?;
    tx.commit().await?;
    // Hand the decision to the platform approval inbox when configured.
    let mut approval = None;
    if st.platform.configured() {
        let req = json!({ "kind": "iot_exception", "title": format!("IoT/OT segmentation exception: {}", obj.get("name").and_then(|v| v.as_str()).unwrap_or("")),
            "details": { "exception_id": id, "justification": obj.get("justification"), "starts_at": starts, "expires_at": expires, "protocol": e.protocol, "port": e.port, "max_op": e.max_op },
            "object_type": "iot_exception", "object_id": id.to_string(), "requested_by": ctx.p.name, "requester_admin_id": (ctx.p.actor_type == ActorType::Admin).then_some(ctx.p.actor_id),
            "required_permission": "policy.iot:activate", "expires_in_hours": 72 });
        match st.platform.create_approval(ctx.tenant(), &req).await {
            Ok(v) => {
                approval = v["data"]["id"].as_str().and_then(|s| Uuid::parse_str(s).ok());
                let mut tx = ctx.tx().await?;
                sqlx::query("UPDATE exceptions SET approval_id = $2 WHERE id = $1").bind(id).bind(approval).execute(&mut *tx).await?;
                tx.commit().await?;
            }
            Err(err) => tracing::warn!(error = %err, "approval inbox unavailable; exception awaits local approval"),
        }
    }
    let mut tx = ctx.tx().await?;
    let row = aether_kit::resource::fetch(&mut tx, &super::resources::EXCEPTIONS, id).await?;
    tx.commit().await?;
    Ok(Envelope::created(&ctx, json!({ "exception": row, "approval_id": approval })).location(format!("/api/v1/exceptions/{id}")))
}

/// Apply an exception decision (local approval or platform approval event).
pub async fn decide_exception(tx: &mut aether_kit::db::Tx, ctx: &Ctx, id: Uuid, action: &str, by: &str) -> ApiResult<Value> {
    let r: Option<(String, Option<Uuid>)> =
        sqlx::query_as("SELECT state, created_by FROM exceptions WHERE id = $1 AND deleted_at IS NULL FOR UPDATE").bind(id).fetch_optional(&mut **tx).await?;
    let (state, creator) = r.ok_or_else(|| ApiError::not_found("exception"))?;
    let new = match (state.as_str(), action) {
        ("pending_approval", "approve") => "approved",
        ("pending_approval", "deny") => "denied",
        ("approved", "revoke") | ("pending_approval", "revoke") => "revoked",
        (s, a) => return Err(ApiError::conflict("invalid_state", format!("cannot {a} an exception that is {s}"))),
    };
    if action == "approve" && ctx.p.actor_type == ActorType::Admin && creator == Some(ctx.p.actor_id) {
        return Err(ApiError::forbidden("the requester cannot approve their own exception"));
    }
    sqlx::query("UPDATE exceptions SET state = $2, decided_by = $3, decided_at = now(), version = version + 1, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(new)
        .bind(by)
        .execute(&mut **tx)
        .await?;
    audit::record(tx, ctx, Entry::new(action, "exception", Some(id)).reason(format!("{state} -> {new} by {by}"))).await?;
    events::emit_simple(tx, ctx, "exception", new, id, None, json!({ "id": id, "state": new })).await?;
    aether_kit::resource::fetch(tx, &super::resources::EXCEPTIONS, id).await
}

async fn exception_action(ctx: Ctx, Path((id, action)): Path<(Uuid, String)>) -> ApiResult<Envelope> {
    match action.as_str() {
        "approve" | "deny" => pre(&ctx, ACTIVATE)?,
        "revoke" => pre(&ctx, UPDATE)?,
        _ => return Err(ApiError::not_found("exception action")),
    }
    let mut tx = ctx.tx().await?;
    let row = decide_exception(&mut tx, &ctx, id, &action, &ctx.p.name.clone()).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, row))
}

/// Staged rollouts of zone modes: `start` applies stage 1, `advance` the
/// next stage, `rollback` restores the previous modes of every zone.
async fn rollout_action(State(st): State<AppState>, ctx: Ctx, Path((id, action)): Path<(Uuid, String)>) -> ApiResult<Envelope> {
    pre(&ctx, ACTIVATE)?;
    let mut tx = ctx.tx().await?;
    let r: Option<(String, i32, Value, String, Value)> =
        sqlx::query_as("SELECT state, current_stage, stages, target_mode, previous_modes FROM rollouts WHERE id = $1 AND deleted_at IS NULL FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let (state, stage, stages, target, mut prev) = r.ok_or_else(|| ApiError::not_found("rollout"))?;
    let stages = stages.as_array().cloned().unwrap_or_default();
    let apply = |i: usize| stages.get(i).and_then(|s| s["zone_ids"].as_array().cloned()).unwrap_or_default();
    let (new_state, new_stage, zones): (&str, i32, Vec<Value>) = match (state.as_str(), action.as_str()) {
        ("draft", "start") => ("in_progress", 1, apply(0)),
        ("in_progress", "advance") if (stage as usize) < stages.len() => {
            (if stage as usize + 1 == stages.len() { "completed" } else { "in_progress" }, stage + 1, apply(stage as usize))
        }
        ("in_progress" | "completed", "rollback") => ("rolled_back", stage, vec![]),
        (s, a) => return Err(ApiError::conflict("invalid_state", format!("cannot {a} a rollout that is {s}"))),
    };
    let mut changed = 0;
    if action == "rollback" {
        if let Some(m) = prev.as_object() {
            for (z, mode) in m {
                changed += sqlx::query("UPDATE zones SET mode = $2, version = version + 1, updated_at = now() WHERE id = $1::uuid")
                    .bind(z)
                    .bind(mode.as_str())
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            }
        }
    } else {
        for z in zones {
            let Some(zid) = z.as_str().and_then(|s| Uuid::parse_str(s).ok()) else { continue };
            let cur: Option<(String,)> = sqlx::query_as("SELECT mode FROM zones WHERE id = $1 AND deleted_at IS NULL").bind(zid).fetch_optional(&mut *tx).await?;
            if let Some((m,)) = cur {
                if prev.get(zid.to_string()).is_none() {
                    prev[zid.to_string()] = json!(m);
                }
                changed += sqlx::query("UPDATE zones SET mode = $2, version = version + 1, updated_at = now() WHERE id = $1")
                    .bind(zid)
                    .bind(&target)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            }
        }
    }
    sqlx::query("UPDATE rollouts SET state = $2, current_stage = $3, previous_modes = $4, version = version + 1, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(new_state)
        .bind(new_stage)
        .bind(&prev)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, &ctx, Entry::new(&format!("rollout_{action}"), "rollout", Some(id)).reason(format!("{state} -> {new_state}, {changed} zones"))).await?;
    events::emit_simple(&mut tx, &ctx, "rollout", new_state, id, None, json!({ "id": id, "stage": new_stage, "zones_changed": changed })).await?;
    let doc = build_snapshot(&mut tx, ctx.tenant(), None).await?;
    let rev = record_revision(&mut tx, ctx.tenant(), &doc, &ctx.p.name, &format!("rollout {id} {action}")).await?;
    tx.commit().await?;
    st.invalidate(ctx.tenant());
    Ok(Envelope::ok(&ctx, json!({ "id": id, "state": new_state, "stage": new_stage, "zones_changed": changed, "revision": rev })))
}
