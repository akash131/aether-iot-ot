//! Edge node APIs (ZTE-IOT sections 3 Site And Sensor Topology, 6 Packet
//! Metadata Collection, 81 Branch Enforcement, 82 Cloud Policy
//! Distribution, 92 Device Access Logging, 117 Sensor/Collector Security;
//! docs/integration.md §6).
//!
//! Only enrolled nodes of an allowed kind (node tokens issued by the
//! platform) reach these endpoints, and only for the sensor bound to their
//! node id; a node never reports for another site.
//!
//! * `POST /api/v1/node/observations` — observation batches (idempotent by
//!   `batch_id`, 429 with `Retry-After` under backpressure).
//! * `GET /api/v1/node/snapshot` — the verified product configuration for
//!   the edge (zones, groups, memberships, approved exceptions, approved
//!   active queries), `ETag` = content hash, `If-None-Match` → 304.
//! * `POST /api/v1/node/status` — capture health, applied revision and
//!   active failure modes (alerts are raised for failure modes).
//! * `POST /api/v1/node/decisions` — aggregated enforcement decisions;
//!   `quarantine` decisions quarantine the source device (action owner).
//! * `POST /api/v1/node/active-queries/{id}/results` — results of approved
//!   active queries (ingested as non-passive observations).

use super::common::node;
use crate::pipeline;
use crate::state::AppState;
use aether_kit::{ApiError, ApiResult, Ctx, Envelope, Extras};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DurationRound, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/node/observations", post(observations))
        .route("/api/v1/node/snapshot", get(snapshot))
        .route("/api/v1/node/status", post(status))
        .route("/api/v1/node/decisions", post(decisions))
        .route("/api/v1/node/active-queries/{id}/results", post(query_results))
}

/// The sensor bound to a node.
pub async fn sensor_of(ctx: &Ctx, node_id: &str) -> ApiResult<(Uuid, Uuid, bool)> {
    let mut tx = ctx.tx().await?;
    let r: Option<(Uuid, Uuid, bool)> =
        sqlx::query_as("SELECT id, site_id, enforcement FROM sensors WHERE node_id = $1 AND deleted_at IS NULL").bind(node_id).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    r.ok_or_else(|| {
        ApiError::conflict("sensor_not_registered", format!("register a sensor bound to node {node_id} (POST /api/v1/sensors with node_id) before sending observations"))
    })
}

async fn observations(State(st): State<AppState>, ctx: Ctx, Extras(x): Extras, Json(mut batch): Json<pipeline::Batch>) -> ApiResult<Envelope> {
    let node_id = node(&ctx, &x)?;
    let (sensor, site, _) = sensor_of(&ctx, &node_id).await?;
    batch.sensor_id = Some(sensor);
    let mut tx = ctx.tx().await?;
    sqlx::query("UPDATE sensors SET last_seen_at = now(), status = 'active' WHERE id = $1").bind(sensor).execute(&mut *tx).await?;
    tx.commit().await?;
    let out = pipeline::ingest(&st, &ctx, Some(site), batch).await?;
    Ok(Envelope::accepted(&ctx, out))
}

fn canonical_hash(v: &Value) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(aether_core::canonical::to_vec(v))))
}

/// Build the edge snapshot of a tenant (optionally limited to one site).
pub async fn build_snapshot(tx: &mut aether_kit::db::Tx, tenant: Uuid, site: Option<Uuid>) -> ApiResult<Value> {
    let (zones,): (Value,) = sqlx::query_as(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'key', key, 'security_level', security_level, 'mode', mode, 'safety_critical', safety_critical) ORDER BY key), '[]') FROM zones WHERE deleted_at IS NULL",
    )
    .fetch_one(&mut **tx)
    .await?;
    let (groups,): (Value,) = sqlx::query_as(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'key', key, 'zone', zone_id, 'priority', priority, 'privileged', privileged, 'min_confidence', min_confidence, 'matcher', match) ORDER BY key), '[]') FROM device_groups WHERE deleted_at IS NULL",
    )
    .fetch_one(&mut **tx)
    .await?;
    let (devices,): (Value,) = sqlx::query_as(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'ip', ip, 'mac', mac, 'groups', group_ids, 'zone', zone_id, 'device_type', device_type, 'category', category,
                 'risk_level', risk_level, 'tier', tier, 'quarantined', quarantined, 'site', site_id, 'evaluated_at', risk_evaluated_at) ORDER BY id), '[]')
         FROM assets WHERE deleted_at IS NULL AND merged_into IS NULL AND lifecycle <> 'decommissioned' AND ($1::uuid IS NULL OR site_id = $1 OR site_id IS NULL)",
    )
    .bind(site)
    .fetch_one(&mut **tx)
    .await?;
    let (exceptions,): (Value,) = sqlx::query_as(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'source_device', source_asset_id, 'destination_device', destination_asset_id, 'source_group', source_group_id, 'destination_group', destination_group_id,
                 'protocol', protocol, 'port', port, 'max_op', max_op, 'starts_at', starts_at, 'expires_at', expires_at) ORDER BY id), '[]')
         FROM exceptions WHERE deleted_at IS NULL AND state = 'approved' AND expires_at > now()",
    )
    .fetch_one(&mut **tx)
    .await?;
    let (queries,): (Value,) = sqlx::query_as(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id', q.id, 'kind', q.kind, 'targets', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'ip', a.ip)), '[]') FROM assets a WHERE a.id = ANY(q.target_ids) AND ($1::uuid IS NULL OR a.site_id = $1)))), '[]')
         FROM active_queries q WHERE q.state = 'approved'",
    )
    .bind(site)
    .fetch_one(&mut **tx)
    .await?;
    let mut doc =
        json!({ "schema": 1, "tenant_id": tenant, "site_id": site, "zones": zones, "groups": groups, "devices": devices, "exceptions": exceptions, "active_queries": queries });
    let hash = canonical_hash(&doc);
    doc["content_hash"] = json!(hash);
    Ok(doc)
}

/// Record a configuration revision when the snapshot changed.
pub async fn record_revision(tx: &mut aether_kit::db::Tx, tenant: Uuid, doc: &Value, actor: &str, note: &str) -> ApiResult<i64> {
    let hash = doc["content_hash"].as_str().unwrap_or_default().to_string();
    let cur: Option<(i64, String)> = sqlx::query_as("SELECT revision, hash FROM config_revisions WHERE active ORDER BY revision DESC LIMIT 1").fetch_optional(&mut **tx).await?;
    if let Some((rev, h)) = &cur {
        if *h == hash {
            return Ok(*rev);
        }
    }
    let rev = cur.map(|c| c.0).unwrap_or(0) + 1;
    sqlx::query("UPDATE config_revisions SET active = false WHERE active").execute(&mut **tx).await?;
    sqlx::query("INSERT INTO config_revisions (id, tenant_id, revision, hash, snapshot, note, created_by, active) VALUES ($1,$2,$3,$4,$5,$6,$7,true)")
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(rev)
        .bind(&hash)
        .bind(doc)
        .bind(note)
        .bind(actor)
        .execute(&mut **tx)
        .await?;
    Ok(rev)
}

async fn snapshot(ctx: Ctx, Extras(x): Extras, headers: HeaderMap) -> ApiResult<Response> {
    let node_id = node(&ctx, &x)?;
    let (_, site, enforcement) = sensor_of(&ctx, &node_id).await?;
    let mut tx = ctx.tx().await?;
    let mut doc = build_snapshot(&mut tx, ctx.tenant(), Some(site)).await?;
    let full = build_snapshot(&mut tx, ctx.tenant(), None).await?;
    let rev = record_revision(&mut tx, ctx.tenant(), &full, "system", "edge snapshot").await?;
    tx.commit().await?;
    doc["revision"] = json!(rev);
    doc["enforcement"] = json!(enforcement);
    let hash = doc["content_hash"].as_str().unwrap_or_default().to_string();
    let etag = format!("\"{hash}\"");
    if headers.get(axum::http::header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        return Ok(axum::http::StatusCode::NOT_MODIFIED.into_response());
    }
    let mut res = Envelope::ok(&ctx, doc).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&etag) {
        res.headers_mut().insert(axum::http::header::ETAG, v);
    }
    Ok(res)
}

/// Verify a snapshot document received by an edge.
pub fn verify_snapshot(doc: &Value) -> bool {
    let Some(h) = doc.get("content_hash").and_then(|v| v.as_str()) else { return false };
    let mut d = doc.clone();
    if let Some(m) = d.as_object_mut() {
        m.remove("content_hash");
        m.remove("revision");
        m.remove("enforcement");
    }
    canonical_hash(&d) == h
}

async fn status(State(st): State<AppState>, ctx: Ctx, Extras(x): Extras, Json(body): Json<Value>) -> ApiResult<Envelope> {
    let node_id = node(&ctx, &x)?;
    let (sensor, site, _) = sensor_of(&ctx, &node_id).await?;
    let mut tx = ctx.tx().await?;
    sqlx::query(
        "INSERT INTO node_status (tenant_id, node_id, sensor_id, last_report, software_version, config_revision, status) VALUES ($1,$2,$3,now(),$4,$5,$6)
         ON CONFLICT (tenant_id, node_id) DO UPDATE SET last_report = now(), sensor_id = EXCLUDED.sensor_id, software_version = EXCLUDED.software_version, config_revision = EXCLUDED.config_revision, status = EXCLUDED.status",
    )
    .bind(ctx.tenant())
    .bind(&node_id)
    .bind(sensor)
    .bind(body["software_version"].as_str())
    .bind(body["config_revision"].as_i64())
    .bind(&body)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE sensors SET last_seen_at = now(), status = 'active', health = $2, software_version = $3 WHERE id = $1")
        .bind(sensor)
        .bind(&body["health"])
        .bind(body["software_version"].as_str())
        .execute(&mut *tx)
        .await?;
    let mut raised = 0;
    for f in body["failures"].as_array().cloned().unwrap_or_default().iter().take(32) {
        let key = f["mode"].as_str().unwrap_or("");
        if let Some(m) = iot_core::failure::mode(key) {
            pipeline::raise_alert(
                &mut tx,
                ctx.tenant(),
                m.alert,
                &format!("{}:{node_id}", m.alert),
                m.severity as i32,
                &format!("{} on sensor at site {site}", m.label),
                json!({ "node_id": node_id, "sensor_id": sensor, "measured": f["measured"], "guidance": m }),
            )
            .await?;
            raised += 1;
        }
    }
    tx.commit().await?;
    let _ = st;
    Ok(Envelope::ok(&ctx, json!({ "recorded": true, "alerts": raised })))
}

async fn decisions(State(st): State<AppState>, ctx: Ctx, Extras(x): Extras, Json(body): Json<Value>) -> ApiResult<Envelope> {
    let node_id = node(&ctx, &x)?;
    let items = body.as_array().cloned().unwrap_or_default();
    if items.len() > 5000 {
        return Err(ApiError::payload_too_large("at most 5000 decision records"));
    }
    let bucket = Utc::now().duration_trunc(chrono::Duration::hours(1)).unwrap_or_else(|_| Utc::now());
    let mut tx = ctx.tx().await?;
    let mut quarantined = vec![];
    for d in &items {
        let rule = d["rule"].as_str().unwrap_or("default").chars().take(200).collect::<String>();
        let enforced = if d["enforced"] == "block" { "block" } else { "allow" };
        let count = d["count"].as_i64().unwrap_or(1).clamp(1, 1_000_000);
        sqlx::query(
            "INSERT INTO decision_stats (tenant_id, bucket, node_id, rule, enforced, count) VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (tenant_id, bucket, node_id, rule, enforced) DO UPDATE SET count = decision_stats.count + EXCLUDED.count",
        )
        .bind(ctx.tenant())
        .bind(bucket)
        .bind(&node_id)
        .bind(&rule)
        .bind(enforced)
        .bind(count)
        .execute(&mut *tx)
        .await?;
        let src = d["source_asset"].as_str().and_then(|s| Uuid::parse_str(s).ok());
        pipeline::log(
            &mut tx,
            ctx.tenant(),
            "iot_decision",
            enforced,
            src,
            d["destination_asset"].as_str().map(String::from),
            json!({ "node_id": node_id, "enforced": enforced, "policy_action": d["policy_action"].as_str().unwrap_or("alert"), "mode": d["mode"].as_str(), "source_asset": d["source_asset"].as_str(),
                    "destination_asset": d["destination_asset"].as_str(), "protocol": d["protocol"].as_str(), "operation_class": d["operation_class"].as_str(), "count": count }),
        )
        .await?;
        if d["policy_action"] == "quarantine" && enforced == "block" {
            if let Some(s) = src {
                let r = sqlx::query("UPDATE assets SET quarantined = true, quarantine_reason = $2, version = version + 1, updated_at = now() WHERE id = $1 AND NOT quarantined AND device_type <> ALL($3)")
                    .bind(s)
                    .bind(format!("quarantined by segmentation rule {rule}"))
                    .bind(iot_core::taxonomy::TYPES.iter().filter(|t| t.safety_sensitive).map(|t| t.key.to_string()).collect::<Vec<_>>())
                    .execute(&mut *tx)
                    .await?;
                if r.rows_affected() > 0 {
                    pipeline::change(&mut tx, ctx.tenant(), s, "quarantined", json!({ "rule": rule, "node_id": node_id }), "policy").await?;
                    quarantined.push(s);
                }
            }
        }
    }
    tx.commit().await?;
    if !quarantined.is_empty() {
        pipeline::reevaluate(&st, ctx.tenant(), &quarantined).await?;
    }
    Ok(Envelope::accepted(&ctx, json!({ "accepted": items.len(), "quarantined": quarantined })))
}

async fn query_results(State(st): State<AppState>, ctx: Ctx, Extras(x): Extras, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    let node_id = node(&ctx, &x)?;
    let (sensor, site, _) = sensor_of(&ctx, &node_id).await?;
    let mut tx = ctx.tx().await?;
    let r: Option<(String,)> = sqlx::query_as("SELECT state FROM active_queries WHERE id = $1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await?;
    match r {
        None => return Err(ApiError::not_found("active query")),
        Some((s,)) if s != "approved" && s != "running" => return Err(ApiError::conflict("invalid_state", format!("the query is {s}"))),
        _ => {}
    }
    sqlx::query("UPDATE active_queries SET state = 'done', results = $2, updated_at = now() WHERE id = $1").bind(id).bind(&body["results"]).execute(&mut *tx).await?;
    tx.commit().await?;
    let obs: Vec<iot_core::model::Observation> = body["observations"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|o| serde_json::from_value(o).ok())
        .map(|mut o: iot_core::model::Observation| {
            o.passive = false;
            o
        })
        .collect();
    let out = pipeline::ingest(&st, &ctx, Some(site), pipeline::Batch { batch_id: Some(format!("aq-{id}")), sensor_id: Some(sensor), observations: obs, stats: None }).await?;
    Ok(Envelope::accepted(&ctx, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_hash_verifies() {
        let mut d = json!({"schema": 1, "zones": [], "devices": [{"id": "a"}]});
        d["content_hash"] = json!(canonical_hash(&d));
        d["revision"] = json!(3);
        assert!(verify_snapshot(&d));
        d["devices"][0]["id"] = json!("b");
        assert!(!verify_snapshot(&d));
    }
}
