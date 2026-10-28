//! Asset inventory API (ZTE-IOT sections 17–21 identity lifecycle,
//! deduplication, merge/split, inventory, ownership and business context;
//! 62/69 risk explanation and prioritisation; 73 quarantine; 99–101
//! inventory, device detail and risk screens; 107 Inventory APIs; 135
//! Lifecycle And Decommissioning; Volume 2 "Device Inventory", "Asset
//! Lifecycle"; AE-IOT-0026 inventory export, AE-IOT-0027 data quality).
//!
//! * `GET /api/v1/assets` — filter (`q` full-text, `site_id`, `device_type`,
//!   `category`, `vendor`, `risk_level`, `tier`, `lifecycle`, `zone_id`,
//!   `group_id`, `quarantined`, `protocol`, `min_risk`, `query` inventory
//!   expression), sort (`priority`, `risk_score`, `last_seen`,
//!   `first_seen`, `confidence`), keyset cursor, `count=true`.
//! * `GET|PATCH /api/v1/assets/{id}` — detail; business context
//!   (`If-Match`).
//! * `GET /api/v1/assets/{id}/{classification|risk|findings|anomalies|timeline|peers|flows|baseline|identities}`.
//! * `PUT|DELETE /api/v1/assets/{id}/override` — classification override.
//! * `POST|DELETE /api/v1/assets/{id}/quarantine`, `POST .../decommission`,
//!   `POST .../lifecycle`, `POST .../baseline/{reset|complete}`.
//! * `POST /api/v1/assets/merge`, `POST /api/v1/assets/{id}/split`.
//! * `GET /api/v1/assets/export?format=csv|json`, `POST /api/v1/assets/import`.
//! * `GET /api/v1/inventory/summary` — counts and data-quality metrics.

use super::common::{cursor, limit, next_cursor, pre, q_uuid};
use crate::pipeline;
use crate::state::{AppState, READ, UPDATE};
use aether_kit::audit::{self, Entry};
use aether_kit::{events, ApiError, ApiResult, Ctx, Envelope};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use iot_core::classify::Override;
use iot_core::model::{Observation, Signal};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/assets", get(list))
        .route("/api/v1/assets/export", get(export))
        .route("/api/v1/assets/import", post(import))
        .route("/api/v1/assets/merge", post(merge))
        .route("/api/v1/inventory/summary", get(summary))
        .route("/api/v1/assets/{id}", get(detail).patch(update))
        .route("/api/v1/assets/{id}/classification", get(classification))
        .route("/api/v1/assets/{id}/override", put(set_override).delete(clear_override))
        .route("/api/v1/assets/{id}/risk", get(risk))
        .route("/api/v1/assets/{id}/findings", get(findings))
        .route("/api/v1/assets/{id}/anomalies", get(anomalies))
        .route("/api/v1/assets/{id}/timeline", get(timeline))
        .route("/api/v1/assets/{id}/peers", get(peers))
        .route("/api/v1/assets/{id}/flows", get(flows))
        .route("/api/v1/assets/{id}/baseline", get(baseline))
        .route("/api/v1/assets/{id}/baseline/{action}", post(baseline_action))
        .route("/api/v1/assets/{id}/identities", get(identities))
        .route("/api/v1/assets/{id}/quarantine", post(quarantine).delete(release))
        .route("/api/v1/assets/{id}/decommission", post(decommission))
        .route("/api/v1/assets/{id}/lifecycle", post(lifecycle))
        .route("/api/v1/assets/{id}/split", post(split))
}

pub const ASSET_COLS: &str = "to_jsonb(a) - 'search' - 'signals'";

pub async fn load(tx: &mut aether_kit::db::Tx, id: Uuid) -> ApiResult<Value> {
    let r: Option<(Value,)> = sqlx::query_as(&format!("SELECT {ASSET_COLS} FROM assets a WHERE id = $1 AND deleted_at IS NULL")).bind(id).fetch_optional(&mut **tx).await?;
    r.map(|x| x.0).ok_or_else(|| ApiError::not_found("asset"))
}

const SORTS: &[(&str, &str, bool)] = &[
    ("priority", "lpad(priority::text, 4, '0')", true),
    ("risk_score", "lpad(risk_score::text, 4, '0')", true),
    ("last_seen", "to_char(last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US')", true),
    ("first_seen", "to_char(first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US')", true),
    ("confidence", "to_char(confidence, 'FM0.000000')", false),
    ("name", "lower(coalesce(name, hostname, mac, ip, ''))", false),
];

/// Filter SQL and binds for the inventory (binds are text, cast in SQL).
fn filters(q: &HashMap<String, String>) -> ApiResult<(Vec<String>, Vec<String>)> {
    let mut wh = vec!["a.deleted_at IS NULL".to_string(), "a.merged_into IS NULL".to_string()];
    let mut binds: Vec<String> = vec![];
    let add = |sql: &str, v: String, binds: &mut Vec<String>, wh: &mut Vec<String>| {
        binds.push(v);
        wh.push(sql.replace("$?", &format!("${}", binds.len())));
    };
    for (k, col) in
        [("device_type", "device_type"), ("category", "category"), ("risk_level", "risk_level"), ("tier", "tier"), ("lifecycle", "lifecycle"), ("ip", "ip"), ("mac", "mac")]
    {
        if let Some(v) = q.get(k).filter(|v| !v.is_empty()) {
            add(&format!("a.{col} = ANY(string_to_array($?, ','))"), v.clone(), &mut binds, &mut wh);
        }
    }
    if let Some(v) = q.get("vendor").filter(|v| !v.is_empty()) {
        add("a.vendor ILIKE '%' || $? || '%'", v.clone(), &mut binds, &mut wh);
    }
    for (k, col) in [("site_id", "site_id"), ("zone_id", "zone_id")] {
        if let Some(u) = q_uuid(q, k)? {
            add(&format!("a.{col} = $?::uuid"), u.to_string(), &mut binds, &mut wh);
        }
    }
    if let Some(u) = q_uuid(q, "group_id")? {
        add("$?::uuid = ANY(a.group_ids)", u.to_string(), &mut binds, &mut wh);
    }
    if let Some(v) = q.get("quarantined") {
        add("a.quarantined = $?::boolean", (v == "true").to_string(), &mut binds, &mut wh);
    }
    if let Some(v) = q.get("protocol").filter(|v| !v.is_empty()) {
        add("$? = ANY(a.protocols)", v.clone(), &mut binds, &mut wh);
    }
    if let Some(v) = q.get("min_risk") {
        let n: i32 = v.parse().map_err(|_| ApiError::field("min_risk", "invalid", "0..100"))?;
        add("a.risk_score >= $?::int", n.to_string(), &mut binds, &mut wh);
    }
    if let Some(v) = q.get("q").filter(|v| !v.trim().is_empty()) {
        let terms: Vec<String> = v
            .split_whitespace()
            .take(8)
            .map(|t| t.chars().filter(|c| c.is_alphanumeric() || matches!(c, '.' | ':' | '-' | '_')).collect::<String>())
            .filter(|t| !t.is_empty())
            .collect();
        if !terms.is_empty() {
            add(
                "(a.search @@ to_tsquery('simple', $?) OR a.ip = split_part($?, ':*', 1) OR a.mac = lower(split_part($?, ':*', 1)))",
                terms.iter().map(|t| format!("{t}:*")).collect::<Vec<_>>().join(" & "),
                &mut binds,
                &mut wh,
            );
        }
    }
    Ok((wh, binds))
}

async fn list(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let lim = limit(&q);
    let s = q.get("sort").map(|s| s.as_str()).unwrap_or("priority");
    let (sort, key, desc) = *SORTS.iter().find(|x| x.0 == s).ok_or_else(|| ApiError::field("sort", "invalid", SORTS.iter().map(|x| x.0).collect::<Vec<_>>().join(", ")))?;
    let _ = sort;
    let (mut wh, mut binds) = filters(&q)?;
    let expr =
        q.get("query").filter(|s| !s.trim().is_empty()).map(|s| iot_core::assertions::parse(s).map_err(|m| ApiError::field("query", "invalid_expression", m))).transpose()?;
    if let Some((k, id)) = cursor(&q)? {
        binds.push(k);
        binds.push(id.to_string());
        let (a, b) = (binds.len() - 1, binds.len());
        wh.push(if desc { format!("({key}, a.id) < (${a}, ${b}::uuid)") } else { format!("({key}, a.id) > (${a}, ${b}::uuid)") });
    }
    let fetch = if expr.is_some() { 5000 } else { lim + 1 };
    let sql = format!(
        "SELECT {ASSET_COLS}, {key} AS sk FROM assets a WHERE {} ORDER BY {key} {dir}, a.id {dir} LIMIT {fetch}",
        wh.join(" AND "),
        dir = if desc { "DESC" } else { "ASC" }
    );
    let mut tx = ctx.tx().await?;
    let mut qy = sqlx::query_as::<_, (Value, String)>(&sql);
    for b in &binds {
        qy = qy.bind(b);
    }
    let mut rows = qy.fetch_all(&mut *tx).await?;
    let total = if q.get("count").map(|c| c == "true").unwrap_or(false) {
        let (wh2, binds2) = filters(&q)?;
        let csql = format!("SELECT count(*) FROM assets a WHERE {}", wh2.join(" AND "));
        let mut cq = sqlx::query_as::<_, (i64,)>(&csql);
        for b in &binds2 {
            cq = cq.bind(b);
        }
        Some(cq.fetch_one(&mut *tx).await?.0)
    } else {
        None
    };
    tx.commit().await?;
    if let Some(e) = &expr {
        rows.retain(|(v, _)| iot_core::assertions::eval(e, v));
    }
    let next = if rows.len() as i64 > lim {
        rows.truncate(lim as usize);
        rows.last().and_then(|(v, k)| v["id"].as_str().and_then(|i| Uuid::parse_str(i).ok()).map(|id| next_cursor(k.clone(), id)))
    } else {
        None
    };
    let env = Envelope::page(&ctx, rows.into_iter().map(|r| r.0).collect(), next);
    Ok(match total {
        Some(t) => env.meta(json!({ "total": t })),
        None => env,
    })
}

async fn detail(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let mut a = load(&mut tx, id).await?;
    let groups: Vec<(Uuid, String, String)> = sqlx::query_as("SELECT id, key, name FROM device_groups WHERE id = ANY($1::uuid[])")
        .bind(a["group_ids"].as_array().map(|x| x.iter().filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok())).collect::<Vec<_>>()).unwrap_or_default())
        .fetch_all(&mut *tx)
        .await?;
    a["groups"] = json!(groups.into_iter().map(|(id, key, name)| json!({"id": id, "key": key, "name": name})).collect::<Vec<_>>());
    let counts: (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM findings WHERE asset_id = $1 AND status = 'open'), (SELECT count(*) FROM anomalies WHERE asset_id = $1 AND status = 'open')")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    a["open_findings"] = json!(counts.0);
    a["open_anomalies"] = json!(counts.1);
    a["safety_sensitive"] = json!(iot_core::taxonomy::get(a["device_type"].as_str().unwrap_or("unknown")).safety_sensitive);
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

const CONTEXT_FIELDS: &[&str] = &["name", "owner", "business_unit", "criticality", "location", "tags", "notes", "scanner", "engineering_station", "pinned_group_ids"];

async fn update(State(st): State<AppState>, ctx: Ctx, Path(id): Path<Uuid>, headers: HeaderMap, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let expected = aether_kit::http::if_match(&headers)?;
    let obj = body.as_object().ok_or_else(|| ApiError::bad_request("expected an object"))?;
    let mut errs = vec![];
    for k in obj.keys() {
        if !CONTEXT_FIELDS.contains(&k.as_str()) {
            errs.push(aether_kit::FieldError { field: k.clone(), code: "not_updatable".into(), message: format!("updatable: {}", CONTEXT_FIELDS.join(", ")) });
        }
    }
    if let Some(c) = obj.get("criticality") {
        if !c.is_null() && !c.as_i64().map(|x| (1..=5).contains(&x)).unwrap_or(false) {
            errs.push(aether_kit::FieldError { field: "criticality".into(), code: "out_of_range".into(), message: "1..5".into() });
        }
    }
    for (k, max) in [("name", 200), ("owner", 320), ("business_unit", 200), ("location", 500), ("notes", 20000)] {
        if obj.get(k).and_then(|v| v.as_str()).map(|s| s.len() > max).unwrap_or(false) {
            errs.push(aether_kit::FieldError { field: k.into(), code: "too_long".into(), message: format!("at most {max} characters") });
        }
    }
    if !errs.is_empty() {
        return Err(ApiError::validation(errs));
    }
    let mut tx = ctx.tx().await?;
    let before = load(&mut tx, id).await?;
    aether_kit::http::require_version(before["version"].as_i64(), expected)?;
    let pinned: Option<Vec<Uuid>> =
        obj.get("pinned_group_ids").map(|v| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().and_then(|s| Uuid::parse_str(s).ok())).collect()).unwrap_or_default());
    if let Some(p) = &pinned {
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM device_groups WHERE id = ANY($1) AND deleted_at IS NULL").bind(p).fetch_one(&mut *tx).await?;
        if n as usize != p.len() {
            return Err(ApiError::field("pinned_group_ids", "invalid_reference", "unknown device group"));
        }
    }
    let tags: Option<Vec<String>> =
        obj.get("tags").map(|v| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.chars().take(64).collect())).take(64).collect()).unwrap_or_default());
    sqlx::query(
        "UPDATE assets SET name = CASE WHEN $2 THEN $3 ELSE name END, owner = CASE WHEN $4 THEN $5 ELSE owner END, business_unit = CASE WHEN $6 THEN $7 ELSE business_unit END,
            criticality = CASE WHEN $8 THEN $9 ELSE criticality END, location = CASE WHEN $10 THEN $11 ELSE location END, tags = coalesce($12, tags), notes = CASE WHEN $13 THEN $14 ELSE notes END,
            scanner = coalesce($15, scanner), engineering_station = coalesce($16, engineering_station), pinned_group_ids = coalesce($17, pinned_group_ids),
            version = version + 1, updated_at = now(), updated_by = $18 WHERE id = $1",
    )
    .bind(id)
    .bind(obj.contains_key("name"))
    .bind(obj.get("name").and_then(|v| v.as_str()))
    .bind(obj.contains_key("owner"))
    .bind(obj.get("owner").and_then(|v| v.as_str()))
    .bind(obj.contains_key("business_unit"))
    .bind(obj.get("business_unit").and_then(|v| v.as_str()))
    .bind(obj.contains_key("criticality"))
    .bind(obj.get("criticality").and_then(|v| v.as_i64()).map(|x| x as i32))
    .bind(obj.contains_key("location"))
    .bind(obj.get("location").and_then(|v| v.as_str()))
    .bind(tags)
    .bind(obj.contains_key("notes"))
    .bind(obj.get("notes").and_then(|v| v.as_str()))
    .bind(obj.get("scanner").and_then(|v| v.as_bool()))
    .bind(obj.get("engineering_station").and_then(|v| v.as_bool()))
    .bind(pinned)
    .bind(ctx.p.actor_id)
    .execute(&mut *tx)
    .await?;
    let after = load(&mut tx, id).await?;
    audit::record(&mut tx, &ctx, Entry::new("update", "asset", Some(id)).before(Some(before)).after(Some(after.clone()))).await?;
    events::emit_simple(&mut tx, &ctx, "iot_asset", "updated", id, after["version"].as_i64(), json!({ "id": id, "changed": obj.keys().collect::<Vec<_>>() })).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "context_updated", json!({ "fields": obj.keys().collect::<Vec<_>>() }), &ctx.p.name).await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &[id]).await?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

async fn classification(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    let hist: Vec<(Value,)> = sqlx::query_as(
        "SELECT jsonb_build_object('at', at, 'device_type', device_type, 'confidence', confidence, 'source', source, 'ruleset_hash', ruleset_hash) FROM classification_history WHERE asset_id = $1 ORDER BY at DESC LIMIT 50",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(
        &ctx,
        json!({ "current": pipeline::explain(&a["classification"]), "override": a["classification_override"], "history": hist.into_iter().map(|h| h.0).collect::<Vec<_>>() }),
    ))
}

async fn set_override(State(st): State<AppState>, ctx: Ctx, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let o: Override = serde_json::from_value(body.clone()).map_err(|e| ApiError::bad_request(format!("invalid override: {e}")))?;
    if o.is_empty() {
        return Err(ApiError::bad_request("an override needs at least one of device_type, vendor, model, os, firmware"));
    }
    o.validate().map_err(|c| ApiError::field("device_type", c, "invalid override"))?;
    let reason = body["reason"].as_str().unwrap_or("").chars().take(1000).collect::<String>();
    let mut tx = ctx.tx().await?;
    let before = load(&mut tx, id).await?;
    sqlx::query("UPDATE assets SET classification_override = $2, version = version + 1, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(serde_json::to_value(&o).unwrap_or_default())
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        &ctx,
        Entry::new("override_classification", "asset", Some(id))
            .before(Some(before["classification_override"].clone()))
            .after(Some(serde_json::to_value(&o).unwrap_or_default()))
            .reason(reason.clone()),
    )
    .await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "classification_overridden", json!({ "override": o, "reason": reason }), &ctx.p.name).await?;
    events::emit_simple(&mut tx, &ctx, "iot_asset", "classification_overridden", id, None, json!({ "id": id, "override": o })).await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &[id]).await?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

async fn clear_override(State(st): State<AppState>, ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let mut tx = ctx.tx().await?;
    load(&mut tx, id).await?;
    sqlx::query("UPDATE assets SET classification_override = '{}', version = version + 1, updated_at = now() WHERE id = $1").bind(id).execute(&mut *tx).await?;
    audit::record(&mut tx, &ctx, Entry::new("clear_override", "asset", Some(id))).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "classification_override_cleared", json!({}), &ctx.p.name).await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &[id]).await?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

async fn risk(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    let hist: Vec<(Value,)> = sqlx::query_as("SELECT jsonb_build_object('at', at, 'score', score, 'level', level, 'factors', factors, 'model_version', model_version) FROM risk_history WHERE asset_id = $1 ORDER BY at DESC LIMIT 100")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, json!({ "current": a["risk"], "evaluated_at": a["risk_evaluated_at"], "history": hist.into_iter().map(|h| h.0).collect::<Vec<_>>() })))
}

async fn sub_list(ctx: &Ctx, id: Uuid, sql: &str, q: &HashMap<String, String>) -> ApiResult<Envelope> {
    pre(ctx, READ)?;
    let mut tx = ctx.tx().await?;
    load(&mut tx, id).await?;
    let rows: Vec<(Value,)> = sqlx::query_as(sql).bind(id).bind(limit(q)).bind(q.get("status").cloned()).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Envelope::ok(ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

async fn findings(ctx: Ctx, Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    sub_list(&ctx, id, "SELECT to_jsonb(f) FROM findings f WHERE asset_id = $1 AND ($3::text IS NULL OR status = $3) ORDER BY severity DESC, key LIMIT $2", &q).await
}

async fn anomalies(ctx: Ctx, Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    sub_list(&ctx, id, "SELECT to_jsonb(x) FROM anomalies x WHERE asset_id = $1 AND ($3::text IS NULL OR status = $3) ORDER BY last_seen DESC LIMIT $2", &q).await
}

async fn timeline(ctx: Ctx, Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    sub_list(&ctx, id, "SELECT to_jsonb(c) FROM asset_changes c WHERE asset_id = $1 AND ($3::text IS NULL OR kind = $3) ORDER BY at DESC, id DESC LIMIT $2", &q).await
}

async fn peers(ctx: Ctx, Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    sub_list(
        &ctx,
        id,
        "SELECT to_jsonb(e) || jsonb_build_object('direction', CASE WHEN from_asset = $1 THEN 'outbound' ELSE 'inbound' END) FROM graph_edges e WHERE (from_asset = $1 OR to_asset = $1) AND ($3::text IS NULL OR $3 = $3) ORDER BY last_seen DESC LIMIT $2",
        &q,
    )
    .await
}

async fn flows(ctx: Ctx, Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    sub_list(&ctx, id, "SELECT to_jsonb(f) FROM flow_rollups f WHERE asset_id = $1 AND ($3::text IS NULL OR protocol = $3) ORDER BY bucket DESC, bytes DESC LIMIT $2", &q).await
}

async fn identities(ctx: Ctx, Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    sub_list(&ctx, id, "SELECT to_jsonb(i) FROM asset_identities i WHERE asset_id = $1 AND ($3::text IS NULL OR key_type = $3) ORDER BY last_seen DESC LIMIT $2", &q).await
}

async fn baseline(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    load(&mut tx, id).await?;
    let b: Option<(Value, String, String)> = sqlx::query_as("SELECT data, network_mode, process_mode FROM baselines WHERE asset_id = $1").bind(id).fetch_optional(&mut *tx).await?;
    let snaps: Vec<(Value,)> = sqlx::query_as("SELECT jsonb_build_object('id', id, 'taken_at', taken_at, 'reason', reason, 'edges', jsonb_array_length(coalesce(jsonb_path_query_array(data, '$.edges.*'), '[]'))) FROM baseline_snapshots WHERE asset_id = $1 ORDER BY taken_at DESC LIMIT 20")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    let Some((data, nm, pm)) = b else { return Ok(Envelope::ok(&ctx, json!({ "network_mode": "learning", "process_mode": "learning", "edges": [], "snapshots": [] }))) };
    let base: iot_core::baseline::Baseline = serde_json::from_value(data).map_err(|e| ApiError::internal(e.to_string()))?;
    let edges: Vec<Value> = base.edges.values().map(|(k, s)| json!({ "edge": k, "stats": s })).collect();
    let allow: Vec<Value> = base.allow_list().into_iter().map(|(k, p, o)| json!({ "edge": k, "protocol": p, "max_op": o })).collect();
    Ok(Envelope::ok(
        &ctx,
        json!({ "network_mode": nm, "process_mode": pm, "started_at": base.started_at, "completed_at": base.completed_at, "edges": edges, "values": base.values, "operations": base.operations, "allow_list": allow,
            "snapshots": snaps.into_iter().map(|s| s.0).collect::<Vec<_>>(), "version": base.version }),
    ))
}

async fn baseline_action(State(st): State<AppState>, ctx: Ctx, Path((id, action)): Path<(Uuid, String)>, body: Option<Json<Value>>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let mut tx = ctx.tx().await?;
    load(&mut tx, id).await?;
    let cur: Option<(Value,)> = sqlx::query_as("SELECT data FROM baselines WHERE asset_id = $1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await?;
    let now = chrono::Utc::now();
    let mut base: iot_core::baseline::Baseline = cur.as_ref().and_then(|c| serde_json::from_value(c.0.clone()).ok()).unwrap_or_else(|| iot_core::baseline::Baseline::new(now));
    if let Some((data,)) = &cur {
        sqlx::query("INSERT INTO baseline_snapshots (id, tenant_id, asset_id, reason, data) VALUES ($1,$2,$3,$4,$5)")
            .bind(Uuid::now_v7())
            .bind(ctx.tenant())
            .bind(id)
            .bind(format!("before {action}"))
            .bind(data)
            .execute(&mut *tx)
            .await?;
    }
    match action.as_str() {
        "reset" => base = iot_core::baseline::Baseline::new(now),
        "complete" => {
            base.network_mode = iot_core::baseline::Mode::Monitoring;
            base.process_mode = iot_core::baseline::Mode::Monitoring;
            base.completed_at = Some(now);
        }
        "relearn-process" => {
            base.process_mode = iot_core::baseline::Mode::Learning;
            base.values.clear();
        }
        _ => return Err(ApiError::not_found("baseline action")),
    }
    base.version += 1;
    sqlx::query(
        "INSERT INTO baselines (tenant_id, asset_id, data, network_mode, process_mode) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id, asset_id) DO UPDATE SET data = EXCLUDED.data, network_mode = EXCLUDED.network_mode, process_mode = EXCLUDED.process_mode, updated_at = now()",
    )
    .bind(ctx.tenant())
    .bind(id)
    .bind(serde_json::to_value(&base).unwrap_or_default())
    .bind(if base.network_mode == iot_core::baseline::Mode::Learning { "learning" } else { "monitoring" })
    .bind(if base.process_mode == iot_core::baseline::Mode::Learning { "learning" } else { "monitoring" })
    .execute(&mut *tx)
    .await?;
    let reason = body.and_then(|b| b["reason"].as_str().map(String::from)).unwrap_or_default();
    audit::record(&mut tx, &ctx, Entry::new(&format!("baseline_{action}"), "asset", Some(id)).reason(reason)).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, &format!("baseline_{action}"), json!({}), &ctx.p.name).await?;
    tx.commit().await?;
    let _ = st;
    Ok(Envelope::ok(&ctx, json!({ "asset_id": id, "network_mode": base.network_mode, "process_mode": base.process_mode })))
}

async fn quarantine(State(st): State<AppState>, ctx: Ctx, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let reason = body["reason"]
        .as_str()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::field("reason", "required", "a reason is required"))?
        .chars()
        .take(1000)
        .collect::<String>();
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    if a["lifecycle"] == "decommissioned" {
        return Err(ApiError::conflict("invalid_state", "the asset is decommissioned"));
    }
    sqlx::query("UPDATE assets SET quarantined = true, quarantine_reason = $2, version = version + 1, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&reason)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, &ctx, Entry::new("quarantine", "asset", Some(id)).reason(reason.clone())).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "quarantined", json!({ "reason": reason }), &ctx.p.name).await?;
    events::emit_simple(
        &mut tx,
        &ctx,
        "iot_asset",
        "quarantined",
        id,
        None,
        json!({ "id": id, "reason": reason, "safety_sensitive": iot_core::taxonomy::get(a["device_type"].as_str().unwrap_or("")).safety_sensitive }),
    )
    .await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &[id]).await?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

async fn release(State(st): State<AppState>, ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let mut tx = ctx.tx().await?;
    load(&mut tx, id).await?;
    sqlx::query("UPDATE assets SET quarantined = false, quarantine_reason = NULL, version = version + 1, updated_at = now() WHERE id = $1").bind(id).execute(&mut *tx).await?;
    audit::record(&mut tx, &ctx, Entry::new("release_quarantine", "asset", Some(id))).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "quarantine_released", json!({}), &ctx.p.name).await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &[id]).await?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

/// Decommission: retire the asset and remove stale references safely
/// (ZTE-IOTINV-153170): group pins and membership, active exceptions,
/// pending and approved access requests, remote access targets.
async fn decommission(ctx: Ctx, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let reason = body["reason"].as_str().unwrap_or("").chars().take(1000).collect::<String>();
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    if a["lifecycle"] == "decommissioned" {
        return Err(ApiError::conflict("invalid_state", "the asset is already decommissioned"));
    }
    sqlx::query(
        "UPDATE assets SET lifecycle = 'decommissioned', decommissioned_at = now(), group_ids = '{}', pinned_group_ids = '{}', zone_id = NULL, quarantined = false, version = version + 1, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let ex = sqlx::query("UPDATE exceptions SET state = 'revoked', updated_at = now(), version = version + 1 WHERE (source_asset_id = $1 OR destination_asset_id = $1) AND state IN ('pending_approval','approved') AND deleted_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let targets: Vec<(Uuid,)> = sqlx::query_as("UPDATE remote_targets SET deleted_at = now(), version = version + 1 WHERE asset_id = $1 AND deleted_at IS NULL RETURNING id")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let tids: Vec<Uuid> = targets.iter().map(|t| t.0).collect();
    let reqs = sqlx::query("UPDATE access_requests SET state = CASE WHEN state = 'approved' THEN 'revoked' ELSE 'cancelled' END, updated_at = now(), version = version + 1 WHERE target_id = ANY($1) AND state IN ('pending_approval','approved')")
        .bind(&tids)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let detail = json!({ "reason": reason, "exceptions_revoked": ex, "remote_targets_removed": tids.len(), "access_requests_closed": reqs });
    audit::record(&mut tx, &ctx, Entry::new("decommission", "asset", Some(id)).reason(reason.clone()).after(Some(detail.clone()))).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "decommissioned", detail.clone(), &ctx.p.name).await?;
    events::emit_simple(&mut tx, &ctx, "iot_asset", "decommissioned", id, None, json!({ "id": id, "detail": detail })).await?;
    let a = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, json!({ "asset": a, "cleanup": detail })))
}

async fn lifecycle(ctx: Ctx, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let to = body["state"].as_str().ok_or_else(|| ApiError::field("state", "required", iot_core::taxonomy::LIFECYCLE.join(", ")))?;
    if to == "decommissioned" || to == "merged" {
        return Err(ApiError::field("state", "use_dedicated_action", "use the decommission or merge actions"));
    }
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    let from = a["lifecycle"].as_str().unwrap_or("discovered");
    if !pipeline::lifecycle_ok(from, to) {
        return Err(ApiError::conflict("invalid_transition", format!("cannot move from {from} to {to}")));
    }
    sqlx::query("UPDATE assets SET lifecycle = $2, version = version + 1, updated_at = now() WHERE id = $1").bind(id).bind(to).execute(&mut *tx).await?;
    audit::record(&mut tx, &ctx, Entry::new("lifecycle", "asset", Some(id)).reason(format!("{from} -> {to}"))).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "lifecycle_changed", json!({ "from": from, "to": to }), &ctx.p.name).await?;
    let a = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

/// Merge duplicates into one asset (section 19).
async fn merge(State(st): State<AppState>, ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let into = body["into"].as_str().and_then(|s| Uuid::parse_str(s).ok()).ok_or_else(|| ApiError::field("into", "required", "asset id"))?;
    let from: Vec<Uuid> = body["from"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().and_then(|s| Uuid::parse_str(s).ok())).collect()).unwrap_or_default();
    if from.is_empty() || from.len() > 50 || from.contains(&into) {
        return Err(ApiError::field("from", "invalid", "1..50 other asset ids"));
    }
    let mut tx = ctx.tx().await?;
    let target = load(&mut tx, into).await?;
    for f in &from {
        let src = load(&mut tx, *f).await?;
        if !src["merged_into"].is_null() {
            return Err(ApiError::conflict("already_merged", format!("{f} is already merged")));
        }
        sqlx::query(
            "UPDATE assets t SET mac = coalesce(t.mac, s.mac), serial = coalesce(t.serial, s.serial), hostname = coalesce(t.hostname, s.hostname), client_id = coalesce(t.client_id, s.client_id),
                 ip = coalesce(t.ip, s.ip), signals = (SELECT jsonb_agg(DISTINCT x) FROM (SELECT jsonb_array_elements(t.signals) x UNION SELECT jsonb_array_elements(s.signals)) y),
                 first_seen = least(t.first_seen, s.first_seen), last_seen = greatest(t.last_seen, s.last_seen), tags = coalesce((SELECT array_agg(DISTINCT x) FROM unnest(t.tags || s.tags) x), '{}'),
                 version = t.version + 1, updated_at = now()
             FROM assets s WHERE t.id = $1 AND s.id = $2",
        )
        .bind(into)
        .bind(f)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE assets SET merged_into = $1, lifecycle = 'merged', version = version + 1, updated_at = now() WHERE id = $2")
            .bind(into)
            .bind(f)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO asset_identities (tenant_id, asset_id, key_type, value, site_id, first_seen, last_seen) SELECT tenant_id, $1, key_type, value, site_id, first_seen, last_seen FROM asset_identities WHERE asset_id = $2 ON CONFLICT DO NOTHING")
            .bind(into)
            .bind(f)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE findings SET asset_id = $1 WHERE asset_id = $2 AND key NOT IN (SELECT key FROM findings WHERE asset_id = $1)")
            .bind(into)
            .bind(f)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE anomalies SET status = 'resolved', resolution = 'merged', resolved_at = now() WHERE asset_id = $1 AND status = 'open'")
            .bind(f)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE remote_targets SET asset_id = $1 WHERE asset_id = $2").bind(into).bind(f).execute(&mut *tx).await?;
        pipeline::change(&mut tx, ctx.tenant(), *f, "merged", json!({ "into": into }), &ctx.p.name).await?;
    }
    pipeline::change(&mut tx, ctx.tenant(), into, "merged_from", json!({ "from": from }), &ctx.p.name).await?;
    audit::record(&mut tx, &ctx, Entry::new("merge", "asset", Some(into)).before(Some(target)).reason(format!("merged {} assets", from.len()))).await?;
    events::emit_simple(&mut tx, &ctx, "iot_asset", "merged", into, None, json!({ "into": into, "from": from })).await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &[into]).await?;
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, into).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, a))
}

/// Split identity keys off an asset into a new asset (section 19).
async fn split(State(st): State<AppState>, ctx: Ctx, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let keys: Vec<(String, String)> =
        body["keys"].as_array().map(|a| a.iter().filter_map(|k| Some((k["key_type"].as_str()?.to_string(), k["value"].as_str()?.to_string()))).collect()).unwrap_or_default();
    if keys.is_empty() || keys.len() > 20 || keys.iter().any(|(t, _)| !["mac", "serial", "hostname", "client_id", "ip", "tls"].contains(&t.as_str())) {
        return Err(ApiError::field("keys", "invalid", "1..20 {key_type, value} identity keys"));
    }
    let mut tx = ctx.tx().await?;
    let a = load(&mut tx, id).await?;
    let new_id = Uuid::now_v7();
    let get = |t: &str| keys.iter().find(|k| k.0 == t).map(|k| k.1.clone());
    sqlx::query("INSERT INTO assets (id, tenant_id, site_id, mac, ip, hostname, serial, client_id, lifecycle, name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)")
        .bind(new_id)
        .bind(ctx.tenant())
        .bind(a["site_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
        .bind(get("mac"))
        .bind(get("ip"))
        .bind(get("hostname"))
        .bind(get("serial"))
        .bind(get("client_id"))
        .bind(body["name"].as_str())
        .execute(&mut *tx)
        .await?;
    for (t, v) in &keys {
        sqlx::query("UPDATE asset_identities SET asset_id = $1 WHERE asset_id = $2 AND key_type = $3 AND value = $4")
            .bind(new_id)
            .bind(id)
            .bind(t)
            .bind(v)
            .execute(&mut *tx)
            .await?;
        let col = match t.as_str() {
            "mac" => "mac",
            "serial" => "serial",
            "hostname" => "hostname",
            "client_id" => "client_id",
            "ip" => "ip",
            _ => "tls_fingerprint",
        };
        sqlx::query(&format!("UPDATE assets SET {col} = NULL WHERE id = $1 AND {col} = $2")).bind(id).bind(v).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE assets SET version = version + 1, updated_at = now() WHERE id = $1").bind(id).execute(&mut *tx).await?;
    pipeline::change(&mut tx, ctx.tenant(), id, "split", json!({ "new_asset": new_id, "keys": keys }), &ctx.p.name).await?;
    pipeline::change(&mut tx, ctx.tenant(), new_id, "split_from", json!({ "asset": id }), &ctx.p.name).await?;
    audit::record(&mut tx, &ctx, Entry::new("split", "asset", Some(id)).reason(format!("new asset {new_id}"))).await?;
    events::emit_simple(&mut tx, &ctx, "iot_asset", "split", id, None, json!({ "from": id, "new": new_id })).await?;
    tx.commit().await?;
    pipeline::reevaluate(&st, ctx.tenant(), &[id, new_id]).await?;
    let mut tx = ctx.tx().await?;
    let n = load(&mut tx, new_id).await?;
    tx.commit().await?;
    Ok(Envelope::created(&ctx, n))
}

const EXPORT_COLS: &[&str] = &[
    "id",
    "name",
    "site_id",
    "mac",
    "ip",
    "hostname",
    "serial",
    "device_type",
    "category",
    "vendor",
    "model",
    "os",
    "firmware",
    "confidence",
    "tier",
    "lifecycle",
    "risk_score",
    "risk_level",
    "priority",
    "zone_id",
    "quarantined",
    "owner",
    "business_unit",
    "criticality",
    "location",
    "first_seen",
    "last_seen",
];

fn csv_cell(v: &Value) -> String {
    let s = match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    // Neutralise spreadsheet formulas and quote.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Inventory export (AE-IOT-0026), filtered like the list (max 100 000 rows).
async fn export(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Response> {
    pre(&ctx, READ)?;
    let (wh, binds) = filters(&q)?;
    let mut tx = ctx.tx().await?;
    let esql = format!("SELECT {ASSET_COLS} FROM assets a WHERE {} ORDER BY a.priority DESC, a.id LIMIT 100000", wh.join(" AND "));
    let mut qy = sqlx::query_as::<_, (Value,)>(&esql);
    for b in &binds {
        qy = qy.bind(b);
    }
    let rows = qy.fetch_all(&mut *tx).await?;
    audit::record(&mut tx, &ctx, Entry::new("export", "asset_inventory", None::<Uuid>).reason(format!("{} rows", rows.len()))).await?;
    tx.commit().await?;
    if q.get("format").map(|f| f == "json").unwrap_or(false) {
        return Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()).into_response());
    }
    let mut out = EXPORT_COLS.join(",");
    out.push('\n');
    for (r,) in rows {
        out.push_str(&EXPORT_COLS.iter().map(|c| csv_cell(&r[*c])).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    Ok(([(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"), (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"iot-inventory.csv\"")], out)
        .into_response())
}

/// Import assets from a CMDB or spreadsheet as integration assertions.
async fn import(State(st): State<AppState>, ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, crate::state::CREATE)?;
    let items = body["assets"].as_array().cloned().unwrap_or_default();
    if items.is_empty() || items.len() > 5000 {
        return Err(ApiError::field("assets", "invalid", "1..5000 assets"));
    }
    let site = body["site_id"].as_str().and_then(|s| Uuid::parse_str(s).ok());
    let now = chrono::Utc::now();
    let mut obs = vec![];
    for it in &items {
        let mut o = Observation::new(now, it["mac"].as_str(), it["ip"].as_str());
        o.passive = false;
        let s = |k: &str| it[k].as_str().map(String::from);
        if let Some(t) = s("device_type") {
            if !iot_core::taxonomy::is_known(&t) {
                return Err(ApiError::field("assets.device_type", "unknown_device_type", t));
            }
        }
        o.signals.push(Signal::Asserted {
            source: s("source").unwrap_or_else(|| "import".into()),
            device_type: s("device_type"),
            vendor: s("vendor"),
            model: s("model"),
            os: s("os"),
            firmware: s("firmware"),
            hostname: s("hostname"),
            confidence: it["confidence"].as_f64().unwrap_or(0.7),
        });
        obs.push(o);
    }
    let out = pipeline::ingest(&st, &ctx, site, pipeline::Batch { batch_id: body["batch_id"].as_str().map(String::from), sensor_id: None, observations: obs, stats: None }).await?;
    let mut tx = ctx.tx().await?;
    audit::record(&mut tx, &ctx, Entry::new("import", "asset_inventory", None::<Uuid>).reason(format!("{} accepted, {} rejected", out.accepted, out.rejected.len()))).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, out))
}

/// Inventory summary and data-quality metrics (AE-IOT-0027).
async fn summary(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let (v,): (Value,) = sqlx::query_as(
        "WITH a AS (SELECT * FROM assets WHERE deleted_at IS NULL AND merged_into IS NULL AND lifecycle <> 'decommissioned')
         SELECT jsonb_build_object(
            'total', (SELECT count(*) FROM a),
            'by_category', (SELECT coalesce(jsonb_object_agg(category, n), '{}') FROM (SELECT category, count(*) n FROM a GROUP BY 1) x),
            'by_type', (SELECT coalesce(jsonb_object_agg(device_type, n), '{}') FROM (SELECT device_type, count(*) n FROM a GROUP BY 1) x),
            'by_risk_level', (SELECT coalesce(jsonb_object_agg(risk_level, n), '{}') FROM (SELECT risk_level, count(*) n FROM a GROUP BY 1) x),
            'by_tier', (SELECT coalesce(jsonb_object_agg(tier, n), '{}') FROM (SELECT tier, count(*) n FROM a GROUP BY 1) x),
            'by_lifecycle', (SELECT coalesce(jsonb_object_agg(lifecycle, n), '{}') FROM (SELECT lifecycle, count(*) n FROM a GROUP BY 1) x),
            'by_site', (SELECT coalesce(jsonb_object_agg(coalesce(site_id::text, 'none'), n), '{}') FROM (SELECT site_id, count(*) n FROM a GROUP BY 1) x),
            'unknown', (SELECT count(*) FROM a WHERE device_type = 'unknown'),
            'high_confidence_share', (SELECT coalesce(round(avg(CASE WHEN tier = 'high' THEN 1.0 ELSE 0.0 END)::numeric, 3), 0) FROM a),
            'quarantined', (SELECT count(*) FROM a WHERE quarantined),
            'randomized_mac', (SELECT count(*) FROM a WHERE randomized_mac),
            'stale', (SELECT count(*) FROM a WHERE last_seen < now() - interval '7 days'),
            'open_findings', (SELECT count(*) FROM findings WHERE status = 'open'),
            'open_anomalies', (SELECT count(*) FROM anomalies WHERE status = 'open'),
            'data_quality', (SELECT coalesce(jsonb_object_agg(device_type, q), '{}') FROM (SELECT device_type, jsonb_build_object('devices', count(*), 'high_confidence', round(avg(CASE WHEN tier = 'high' THEN 1.0 ELSE 0.0 END)::numeric, 3)) q FROM a GROUP BY 1) x)
         )",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_neutralises_formulas() {
        assert_eq!(csv_cell(&json!("=cmd()")), "\"'=cmd()\"");
        assert_eq!(csv_cell(&json!("a\"b")), "\"a\"\"b\"");
        assert_eq!(csv_cell(&Value::Null), "\"\"");
    }

    #[test]
    fn filters_bind_every_value() {
        let q: HashMap<String, String> =
            [("device_type", "plc,rtu"), ("q", "rockwell 10.0"), ("min_risk", "40"), ("quarantined", "true")].into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let (wh, binds) = filters(&q).unwrap();
        assert_eq!(binds.len(), 4);
        assert!(wh.iter().all(|w| !w.contains("rockwell")), "values are bound, never interpolated");
        assert!(filters(&[("min_risk".to_string(), "x".to_string())].into_iter().collect()).is_err());
    }
}
