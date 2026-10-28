//! Findings, vulnerability feed, anomalies, alerts and active queries
//! (ZTE-IOT sections 5 Active Discovery Safeguards, 52 Protocol Anomaly
//! Detection, 63–66 vulnerability context, 95–96 risk and anomaly events;
//! Volume 2 "Anomaly Signals"; AE-IOT-0002 learned acknowledgement,
//! AE-IOT-0007/0008 active query governance, AE-IOT-0015 vulnerability
//! acknowledgement, AE-IOT-0028 alert tuning).
//!
//! * `GET /api/v1/findings`, `POST /api/v1/findings/{id}/{acknowledge|resolve|reopen}`
//! * `GET /api/v1/vulnerability-feed`, `POST /api/v1/vulnerability-feed/refresh`,
//!   `GET /api/v1/vulnerability-feed/lookup?vendor=&model=&firmware=`
//! * `GET /api/v1/anomalies`, `POST /api/v1/anomalies/{id}/{acknowledge|resolve|false_positive|learned}`
//! * `GET /api/v1/alerts`, `POST /api/v1/alerts/{id}/{acknowledge|resolve}`
//! * `GET|POST /api/v1/active-queries`, `POST /api/v1/active-queries/{id}/{approve|cancel}`

use super::common::{limit, pre, q_uuid};
use crate::pipeline;
use crate::state::{AppState, ACTIVATE, CREATE, READ, UPDATE};
use aether_kit::audit::{self, Entry};
use aether_kit::{events, ActorType, ApiError, ApiResult, Ctx, Envelope};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use iot_core::vuln::VulnFeed;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/findings", get(findings))
        .route("/api/v1/findings/{id}/{action}", post(finding_action))
        .route("/api/v1/vulnerability-feed", get(feed_status))
        .route("/api/v1/vulnerability-feed/refresh", post(feed_refresh))
        .route("/api/v1/vulnerability-feed/lookup", get(feed_lookup))
        .route("/api/v1/anomalies", get(anomalies))
        .route("/api/v1/anomalies/{id}/{action}", post(anomaly_action))
        .route("/api/v1/alerts", get(alerts))
        .route("/api/v1/alerts/{id}/{action}", post(alert_action))
        .route("/api/v1/active-queries", get(queries).post(plan_query))
        .route("/api/v1/active-queries/{id}/{action}", post(query_action))
}

async fn findings(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT to_jsonb(f) || jsonb_build_object('asset', jsonb_build_object('name', coalesce(a.name, a.hostname, a.mac, a.ip), 'device_type', a.device_type, 'priority', a.priority))
         FROM findings f JOIN assets a ON a.id = f.asset_id
         WHERE ($1::text IS NULL OR f.kind = $1) AND ($2::text IS NULL OR f.status = ANY(string_to_array($2, ','))) AND ($3::float8 IS NULL OR f.severity >= $3)
           AND ($4::uuid IS NULL OR f.asset_id = $4) AND ($5::boolean IS NULL OR f.known_exploited = $5)
         ORDER BY f.known_exploited DESC, f.severity DESC, a.priority DESC, f.id LIMIT $6",
    )
    .bind(q.get("kind"))
    .bind(q.get("status").cloned().or(Some("open,acknowledged".into())))
    .bind(q.get("min_severity").and_then(|v| v.parse::<f64>().ok()))
    .bind(q_uuid(&q, "asset_id")?)
    .bind(q.get("known_exploited").map(|v| v == "true"))
    .bind(limit(&q))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

async fn finding_action(ctx: Ctx, Path((id, action)): Path<(Uuid, String)>, body: Option<Json<Value>>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let reason = body.as_ref().and_then(|b| b["reason"].as_str()).map(|s| s.chars().take(2000).collect::<String>());
    let (to, from): (&str, &[&str]) = match action.as_str() {
        "acknowledge" => ("acknowledged", &["open"]),
        "resolve" => ("resolved", &["open", "acknowledged"]),
        "reopen" => ("open", &["acknowledged", "resolved"]),
        _ => return Err(ApiError::not_found("finding action")),
    };
    if to == "acknowledged" && reason.is_none() {
        return Err(ApiError::field("reason", "required", "acknowledging a finding needs a reason (risk acceptance)"));
    }
    let mut tx = ctx.tx().await?;
    let r: Option<(Value,)> = sqlx::query_as(
        "UPDATE findings SET status = $2, acknowledged_by = CASE WHEN $2 = 'acknowledged' THEN $3 ELSE acknowledged_by END, acknowledged_at = CASE WHEN $2 = 'acknowledged' THEN now() ELSE acknowledged_at END,
             ack_reason = coalesce($4, ack_reason), resolved_at = CASE WHEN $2 = 'resolved' THEN now() ELSE NULL END
         WHERE id = $1 AND status = ANY($5) RETURNING to_jsonb(findings)",
    )
    .bind(id)
    .bind(to)
    .bind(&ctx.p.name)
    .bind(&reason)
    .bind(from)
    .fetch_optional(&mut *tx)
    .await?;
    let row = r.ok_or_else(|| ApiError::conflict("invalid_state", format!("the finding cannot be moved to {to}")))?.0;
    audit::record(&mut tx, &ctx, Entry::new(&action, "finding", Some(id)).reason(reason.unwrap_or_default())).await?;
    events::emit_simple(&mut tx, &ctx, "iot_finding", to, id, None, row.clone()).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, row))
}

async fn feed_status(State(st): State<AppState>, ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let f = st.feed();
    Ok(Envelope::ok(
        &ctx,
        json!({ "name": f.name(), "version": f.version(), "age_secs": st.feed_age_secs(), "source": st.cfg.peers.vuln_feed_url.as_deref().unwrap_or("bundled sample feed (synthetic advisories)") }),
    ))
}

/// Load the feed from the configured URL (falls back to the current one).
pub async fn refresh_feed(st: &AppState) -> Result<String, String> {
    let Some(url) = st.cfg.peers.vuln_feed_url.clone() else {
        st.set_feed(Arc::new(iot_core::vuln::OfflineFeed::sample()));
        return Ok("sample".into());
    };
    let res = st.platform.http().get(&url).timeout(std::time::Duration::from_secs(30)).send().await.map_err(|e| e.without_url().to_string())?;
    if !res.status().is_success() {
        return Err(format!("feed returned {}", res.status()));
    }
    let text = res.text().await.map_err(|e| e.to_string())?;
    if text.len() > 200 * 1024 * 1024 {
        return Err("feed document too large".into());
    }
    let f = iot_core::vuln::OfflineFeed::from_json(&text)?;
    let v = f.version().to_string();
    st.set_feed(Arc::new(f));
    Ok(v)
}

async fn feed_refresh(State(st): State<AppState>, ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let v = refresh_feed(&st).await.map_err(|e| ApiError::unavailable(format!("vulnerability feed refresh failed: {e}")))?;
    audit::record_standalone(&ctx, Entry::new("refresh", "vulnerability_feed", None::<Uuid>).reason(v.clone())).await;
    // Re-assess every asset with a vendor and model under the new feed.
    let mut tx = ctx.tx().await?;
    let ids: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM assets WHERE vendor IS NOT NULL AND model IS NOT NULL AND merged_into IS NULL AND deleted_at IS NULL LIMIT 50000")
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    let n = pipeline::reevaluate(&st, ctx.tenant(), &ids.into_iter().map(|i| i.0).collect::<Vec<_>>()).await?;
    Ok(Envelope::ok(&ctx, json!({ "version": v, "reassessed": n })))
}

async fn feed_lookup(State(st): State<AppState>, ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let vendor = q.get("vendor").ok_or_else(|| ApiError::field("vendor", "required", "vendor"))?;
    let model = q.get("model").ok_or_else(|| ApiError::field("model", "required", "model"))?;
    let fw = q.get("firmware").map(|s| s.as_str());
    let f = st.feed();
    Ok(Envelope::ok(
        &ctx,
        json!({ "cpe": iot_core::vuln::cpe(vendor, model, fw), "advisories": f.advisories(vendor, model, fw), "end_of_life": f.end_of_life(vendor, model), "default_credentials": f.default_credentials(vendor, model) }),
    ))
}

async fn anomalies(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT to_jsonb(x) || jsonb_build_object('asset', jsonb_build_object('name', coalesce(a.name, a.hostname, a.mac, a.ip), 'device_type', a.device_type, 'zone_id', a.zone_id))
         FROM anomalies x JOIN assets a ON a.id = x.asset_id
         WHERE ($1::text IS NULL OR x.kind = ANY(string_to_array($1, ','))) AND ($2::text IS NULL OR x.status = ANY(string_to_array($2, ','))) AND ($3::float8 IS NULL OR x.severity >= $3) AND ($4::uuid IS NULL OR x.asset_id = $4)
         ORDER BY x.last_seen DESC, x.id DESC LIMIT $5",
    )
    .bind(q.get("kind"))
    .bind(q.get("status").cloned().or(Some("open,acknowledged".into())))
    .bind(q.get("min_severity").and_then(|v| v.parse::<f64>().ok()))
    .bind(q_uuid(&q, "asset_id")?)
    .bind(limit(&q))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

async fn anomaly_action(ctx: Ctx, Path((id, action)): Path<(Uuid, String)>, body: Option<Json<Value>>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let comment = body.as_ref().and_then(|b| b["comment"].as_str()).map(|s| s.chars().take(2000).collect::<String>());
    let to = match action.as_str() {
        "acknowledge" => "acknowledged",
        "resolve" => "resolved",
        "false_positive" => "false_positive",
        "learned" => "learned",
        _ => return Err(ApiError::not_found("anomaly action")),
    };
    let mut tx = ctx.tx().await?;
    let r: Option<(Uuid, String, Value, String)> =
        sqlx::query_as("SELECT asset_id, kind, evidence, status FROM anomalies WHERE id = $1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await?;
    let (asset, kind, evidence, status) = r.ok_or_else(|| ApiError::not_found("anomaly"))?;
    if !["open", "acknowledged"].contains(&status.as_str()) {
        return Err(ApiError::conflict("invalid_state", format!("the anomaly is {status}")));
    }
    let mut learned = false;
    if to == "learned" {
        // Absorb the deviation into the baseline so it no longer alerts.
        if let Ok(edge) = serde_json::from_value::<iot_core::baseline::EdgeKey>(evidence["edge"].clone()) {
            let b: Option<(Value,)> = sqlx::query_as("SELECT data FROM baselines WHERE asset_id = $1 FOR UPDATE").bind(asset).fetch_optional(&mut *tx).await?;
            if let Some(mut base) = b.and_then(|b| serde_json::from_value::<iot_core::baseline::Baseline>(b.0).ok()) {
                let max_op = evidence["observed_max_op"].as_str().or(evidence["max_op"].as_str()).and_then(iot_core::segmentation::op_class);
                let f = iot_core::model::Flow {
                    peer_ip: edge.peer.clone(),
                    peer_mac: None,
                    transport: edge.transport.clone(),
                    port: edge.port,
                    outbound: edge.outbound,
                    packets: 1,
                    bytes: 0,
                    protocol: evidence["protocol"].as_str().and_then(iot_core::protocols::Protocol::parse),
                    max_op,
                    operations: vec![],
                };
                base.learn_edge(&f, chrono::Utc::now());
                if let Some((_, s)) = base.edges.values_mut().find(|(k, _)| *k == edge) {
                    if max_op > s.max_op {
                        s.max_op = max_op;
                    }
                }
                sqlx::query("UPDATE baselines SET data = $2, updated_at = now() WHERE asset_id = $1")
                    .bind(asset)
                    .bind(serde_json::to_value(&base).unwrap_or_default())
                    .execute(&mut *tx)
                    .await?;
                learned = true;
            }
        }
        if !learned && kind != "process_value_out_of_range" {
            return Err(ApiError::conflict("not_learnable", "this anomaly has no communication edge to learn"));
        }
    }
    let (row,): (Value,) = sqlx::query_as("UPDATE anomalies SET status = $2, resolved_by = $3, resolved_at = now(), resolution = $4 WHERE id = $1 RETURNING to_jsonb(anomalies)")
        .bind(id)
        .bind(to)
        .bind(&ctx.p.name)
        .bind(&comment)
        .fetch_one(&mut *tx)
        .await?;
    audit::record(&mut tx, &ctx, Entry::new(&action, "anomaly", Some(id)).reason(comment.unwrap_or_default())).await?;
    events::emit_simple(&mut tx, &ctx, "iot_anomaly", to, id, None, json!({ "id": id, "asset_id": asset, "learned": learned })).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, row))
}

async fn alerts(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT to_jsonb(x) FROM alerts x WHERE ($1::text IS NULL OR status = ANY(string_to_array($1, ','))) AND ($2::text IS NULL OR kind = $2) ORDER BY last_seen DESC LIMIT $3",
    )
    .bind(q.get("status").cloned().or(Some("open,acknowledged".into())))
    .bind(q.get("kind"))
    .bind(limit(&q))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

async fn alert_action(ctx: Ctx, Path((id, action)): Path<(Uuid, String)>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let to = match action.as_str() {
        "acknowledge" => "acknowledged",
        "resolve" => "resolved",
        _ => return Err(ApiError::not_found("alert action")),
    };
    let mut tx = ctx.tx().await?;
    let r: Option<(Value,)> = sqlx::query_as(
        "UPDATE alerts SET status = $2, resolved_at = CASE WHEN $2 = 'resolved' THEN now() ELSE resolved_at END WHERE id = $1 AND status <> 'resolved' RETURNING to_jsonb(alerts)",
    )
    .bind(id)
    .bind(to)
    .fetch_optional(&mut *tx)
    .await?;
    let row = r.ok_or_else(|| ApiError::conflict("invalid_state", "the alert is resolved or unknown"))?.0;
    audit::record(&mut tx, &ctx, Entry::new(&action, "alert", Some(id))).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, row))
}

async fn queries(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as("SELECT to_jsonb(q) FROM active_queries q WHERE ($1::text IS NULL OR state = $1) ORDER BY created_at DESC LIMIT $2")
        .bind(q.get("state"))
        .bind(limit(&q))
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

/// Plan an active query (passive by default; explicit authorisation for
/// anything active, approval for caution/intrusive queries and
/// safety-sensitive targets).
async fn plan_query(State(st): State<AppState>, ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, CREATE)?;
    let kind = body["kind"].as_str().ok_or_else(|| ApiError::field("kind", "required", iot_core::policy::QUERY_KINDS.join(", ")))?;
    let (_, risk, _, _, _) = iot_core::activeq::query(kind).ok_or_else(|| ApiError::field("kind", "unknown_query", iot_core::policy::QUERY_KINDS.join(", ")))?;
    let ids: Vec<Uuid> = body["target_ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().and_then(|s| Uuid::parse_str(s).ok())).collect()).unwrap_or_default();
    if ids.is_empty() || ids.len() > 500 {
        return Err(ApiError::field("target_ids", "invalid", "1..500 asset ids"));
    }
    let mut tx = ctx.tx().await?;
    let settings: iot_core::activeq::Settings = serde_json::from_value(pipeline::settings(&mut tx, "active_queries").await?).unwrap_or_default();
    let rows: Vec<(Uuid, Option<String>, String, String)> =
        sqlx::query_as("SELECT id, ip, category, device_type FROM assets WHERE id = ANY($1) AND merged_into IS NULL AND deleted_at IS NULL").bind(&ids).fetch_all(&mut *tx).await?;
    let (attempts,): (Value,) = sqlx::query_as("SELECT coalesce(jsonb_object_agg(t, n), '{}') FROM (SELECT unnest(target_ids)::text t, count(*) n FROM active_queries WHERE created_at > now() - interval '1 day' GROUP BY 1) x").fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let targets: Vec<iot_core::activeq::Target> = rows
        .iter()
        .map(|(id, ip, cat, ty)| iot_core::activeq::Target {
            id: id.to_string(),
            ip: ip.clone().unwrap_or_default(),
            category: cat.clone(),
            device_type: ty.clone(),
            safety_sensitive: iot_core::taxonomy::get(ty).safety_sensitive,
            attempts_today: attempts[id.to_string()].as_u64().unwrap_or(0) as u32,
        })
        .collect();
    let now = chrono::Utc::now();
    let needs_approval = targets.iter().any(|t| t.safety_sensitive) || risk > iot_core::activeq::Risk::Safe;
    let plan_approved = iot_core::activeq::plan(&settings, kind, &targets, true, now);
    let plan_unapproved = iot_core::activeq::plan(&settings, kind, &targets, false, now);
    let allowed: Vec<Uuid> = plan_approved.iter().filter(|p| p.allowed).filter_map(|p| Uuid::parse_str(&p.target).ok()).collect();
    if allowed.is_empty() {
        return Err(ApiError::conflict("nothing_allowed", "no target may be queried").with_extra(json!({ "plan": plan_approved })));
    }
    let auto = !needs_approval && plan_unapproved.iter().all(|p| p.allowed);
    let id = Uuid::now_v7();
    let mut tx = ctx.tx().await?;
    sqlx::query("INSERT INTO active_queries (id, tenant_id, kind, target_ids, state, plan, requested_by) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(id)
        .bind(ctx.tenant())
        .bind(kind)
        .bind(&allowed)
        .bind(if auto { "approved" } else { "pending_approval" })
        .bind(json!(plan_approved))
        .bind(&ctx.p.name)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, &ctx, Entry::new("plan_active_query", "active_query", Some(id)).reason(format!("{kind} on {} targets", allowed.len()))).await?;
    events::emit_simple(&mut tx, &ctx, "active_query", if auto { "approved" } else { "requested" }, id, None, json!({ "id": id, "kind": kind, "targets": allowed.len() })).await?;
    tx.commit().await?;
    if !auto && st.platform.configured() {
        let req = json!({ "kind": "iot_active_query", "title": format!("Active query {kind} on {} devices", allowed.len()), "details": { "active_query_id": id, "kind": kind, "risk": risk, "targets": allowed },
            "object_type": "iot_active_query", "object_id": id.to_string(), "requested_by": ctx.p.name, "requester_admin_id": (ctx.p.actor_type == ActorType::Admin).then_some(ctx.p.actor_id),
            "required_permission": "policy.iot:activate", "expires_in_hours": 24 });
        if let Ok(v) = st.platform.create_approval(ctx.tenant(), &req).await {
            let mut tx = ctx.tx().await?;
            sqlx::query("UPDATE active_queries SET approval_id = $2 WHERE id = $1")
                .bind(id)
                .bind(v["data"]["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
    }
    let mut tx = ctx.tx().await?;
    let (row,): (Value,) = sqlx::query_as("SELECT to_jsonb(q) FROM active_queries q WHERE id = $1").bind(id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(Envelope::created(&ctx, row))
}

async fn query_action(ctx: Ctx, Path((id, action)): Path<(Uuid, String)>) -> ApiResult<Envelope> {
    let (to, from) = match action.as_str() {
        "approve" => {
            pre(&ctx, ACTIVATE)?;
            ("approved", "pending_approval")
        }
        "cancel" => {
            pre(&ctx, UPDATE)?;
            ("cancelled", "*")
        }
        _ => return Err(ApiError::not_found("active query action")),
    };
    let mut tx = ctx.tx().await?;
    let r: Option<(Value,)> = sqlx::query_as("UPDATE active_queries SET state = $2, updated_at = now() WHERE id = $1 AND ($3 = '*' AND state IN ('planned','pending_approval','approved') OR state = $3) RETURNING to_jsonb(active_queries)")
        .bind(id)
        .bind(to)
        .bind(from)
        .fetch_optional(&mut *tx)
        .await?;
    let row = r.ok_or_else(|| ApiError::conflict("invalid_state", format!("cannot {action} this query")))?.0;
    if to == "approved" && row["requested_by"].as_str() == Some(&ctx.p.name) && ctx.p.actor_type == ActorType::Admin {
        return Err(ApiError::forbidden("the requester cannot approve their own active query"));
    }
    audit::record(&mut tx, &ctx, Entry::new(&action, "active_query", Some(id))).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, row))
}
