//! Privileged remote access to OT assets (ZTE-IOT sections 86 Temporary
//! Access Workflow, 87 Vendor Remote Access, 88 Third-Party Maintenance
//! Access, 89 Privileged OT Access, 90 Session Approval, 91 Session
//! Auditing; Volume 2 "Access Mediation"; ZTE-IOTINV-153166;
//! AE-IOT-0021..0025).
//!
//! * `POST /api/v1/access-requests` — request a just-in-time window to a
//!   remote target for a vendor principal or user; validated against the
//!   tenant limits and the `iot.remote_access` policy; approvals go to the
//!   platform approval inbox (or local approval when the platform is not
//!   configured). `GET` lists them.
//! * `POST /api/v1/access-requests/{id}/{approve|deny|cancel|revoke}`.
//! * `POST /api/v1/access-requests/{id}/sessions` — start a session inside
//!   the approved window (browser session brokered by Private Access; the
//!   response names the console to launch).
//! * `GET /api/v1/remote-sessions`, `POST /api/v1/remote-sessions/{id}/{activity|end|terminate}`,
//!   `PUT /api/v1/remote-sessions/{id}/recording` — supervision and
//!   recording metadata (integrity digest; content stays with the broker).

use super::common::{body_str, limit, pre};
use crate::pipeline;
use crate::state::{AppState, ACTIVATE, CREATE, READ, UPDATE};
use aether_kit::audit::{self, Entry};
use aether_kit::{events, ActorType, ApiError, ApiResult, Ctx, Envelope};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use iot_core::remote::{self, Limits, RecordingMeta, RequestState};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/access-requests", get(list).post(create))
        .route("/api/v1/access-requests/{id}", get(get_one))
        .route("/api/v1/access-requests/{id}/sessions", post(start_session))
        .route("/api/v1/access-requests/{id}/{action}", post(action))
        .route("/api/v1/remote-sessions", get(sessions))
        .route("/api/v1/remote-sessions/{id}", get(session))
        .route("/api/v1/remote-sessions/{id}/recording", put(recording))
        .route("/api/v1/remote-sessions/{id}/{action}", post(session_action))
}

pub async fn limits(tx: &mut aether_kit::db::Tx) -> ApiResult<Limits> {
    Ok(serde_json::from_value(pipeline::settings(tx, "remote_access").await?).unwrap_or_default())
}

async fn load(tx: &mut aether_kit::db::Tx, id: Uuid) -> ApiResult<Value> {
    let r: Option<(Value,)> = sqlx::query_as("SELECT to_jsonb(r) FROM access_requests r WHERE id = $1").bind(id).fetch_optional(&mut **tx).await?;
    r.map(|x| x.0).ok_or_else(|| ApiError::not_found("access request"))
}

async fn list(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT to_jsonb(r) FROM access_requests r WHERE ($1::text IS NULL OR state = ANY(string_to_array($1, ','))) AND ($2::text IS NULL OR target_id::text = $2) AND ($3::text IS NULL OR vendor_principal_id::text = $3)
         ORDER BY created_at DESC LIMIT $4",
    )
    .bind(q.get("state"))
    .bind(q.get("target_id"))
    .bind(q.get("vendor_principal_id"))
    .bind(limit(&q))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

async fn get_one(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let mut r = load(&mut tx, id).await?;
    let s: Vec<(Value,)> = sqlx::query_as("SELECT to_jsonb(s) FROM remote_sessions s WHERE request_id = $1 ORDER BY started_at DESC").bind(id).fetch_all(&mut *tx).await?;
    r["sessions"] = json!(s.into_iter().map(|x| x.0).collect::<Vec<_>>());
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, r))
}

async fn create(State(st): State<AppState>, ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, CREATE)?;
    let target_id = body["target_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()).ok_or_else(|| ApiError::field("target_id", "required", "remote target id"))?;
    let vendor_id = body["vendor_principal_id"].as_str().map(|s| Uuid::parse_str(s).map_err(|_| ApiError::field("vendor_principal_id", "invalid_uuid", "UUID"))).transpose()?;
    let t = |k: &str| body[k].as_str().and_then(|s| s.parse::<DateTime<Utc>>().ok()).ok_or_else(|| ApiError::field(k, "required", "RFC 3339 timestamp"));
    let (start, end) = (t("window_start")?, t("window_end")?);
    let protocol = body_str(&body, "protocol").unwrap_or("https").to_string();
    let justification = body_str(&body, "justification").unwrap_or("").chars().take(2000).collect::<String>();
    let ticket = body_str(&body, "ticket").map(|s| s.chars().take(200).collect::<String>());
    let now = Utc::now();
    let mut tx = ctx.tx().await?;
    let tg: Option<(Value,)> = sqlx::query_as("SELECT to_jsonb(t) FROM remote_targets t WHERE id = $1 AND deleted_at IS NULL").bind(target_id).fetch_optional(&mut *tx).await?;
    let tg = tg.ok_or_else(|| ApiError::field("target_id", "invalid_reference", "unknown remote target"))?.0;
    let available = match tg["asset_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()) {
        Some(a) => {
            let r: Option<(String,)> = sqlx::query_as("SELECT lifecycle FROM assets WHERE id = $1").bind(a).fetch_optional(&mut *tx).await?;
            r.map(|x| x.0 != "decommissioned").unwrap_or(false)
        }
        None => true,
    };
    let (email, p_exp, p_enabled, vendor_name, allowed_groups): (String, Option<DateTime<Utc>>, Option<bool>, Option<String>, Vec<Uuid>) = match vendor_id {
        Some(v) => {
            let r: Option<(String, DateTime<Utc>, bool, String, Vec<Uuid>)> =
                sqlx::query_as("SELECT email, expires_at, enabled, company, allowed_group_ids FROM vendor_principals WHERE id = $1 AND deleted_at IS NULL")
                    .bind(v)
                    .fetch_optional(&mut *tx)
                    .await?;
            let (e, x, en, c, g) = r.ok_or_else(|| ApiError::field("vendor_principal_id", "invalid_reference", "unknown vendor principal"))?;
            (e, Some(x), Some(en), Some(c), g)
        }
        None => (body_str(&body, "requester_email").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| ctx.p.name.clone()), None, None, None, vec![]),
    };
    // Vendor scope: the target asset must be in one of the vendor's groups (least privilege).
    if vendor_id.is_some() && !allowed_groups.is_empty() {
        if let Some(a) = tg["asset_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()) {
            let (ok,): (bool,) =
                sqlx::query_as("SELECT coalesce((SELECT group_ids && $2 FROM assets WHERE id = $1), false)").bind(a).bind(&allowed_groups).fetch_one(&mut *tx).await?;
            if !ok {
                return Err(ApiError::forbidden("the target is outside the vendor principal's allowed device groups"));
            }
        }
    }
    let lim = limits(&mut tx).await?;
    let input = remote::RequestInput {
        window_start: start,
        window_end: end,
        protocol: protocol.clone(),
        justification: justification.clone(),
        ticket: ticket.clone(),
        principal_expires_at: p_exp,
        principal_enabled: p_enabled,
        target_protocols: tg["protocols"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        target_available: available,
    };
    remote::validate(&input, &lim, now).map_err(|c| ApiError::field("window_start", c, "invalid access request"))?;
    let id = Uuid::now_v7();
    let requester_admin = (ctx.p.actor_type == ActorType::Admin).then_some(ctx.p.actor_id);
    sqlx::query(
        "INSERT INTO access_requests (id, tenant_id, vendor_principal_id, requester_email, requester_admin_id, target_id, protocol, justification, ticket, window_start, window_end, state)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending_approval')",
    )
    .bind(id)
    .bind(ctx.tenant())
    .bind(vendor_id)
    .bind(&email)
    .bind(requester_admin)
    .bind(target_id)
    .bind(&protocol)
    .bind(&justification)
    .bind(&ticket)
    .bind(start)
    .bind(end)
    .execute(&mut *tx)
    .await?;
    audit::record(&mut tx, &ctx, Entry::new("request", "access_request", Some(id)).reason(justification.clone())).await?;
    events::emit_simple(
        &mut tx,
        &ctx,
        "access_request",
        "requested",
        id,
        Some(1),
        json!({ "id": id, "target_id": target_id, "vendor": vendor_name, "window_start": start, "window_end": end }),
    )
    .await?;
    pipeline::log(
        &mut tx,
        ctx.tenant(),
        "iot_remote_access",
        "request",
        None,
        Some(tg["name"].as_str().unwrap_or("").into()),
        json!({ "request_id": id.to_string(), "event": "requested", "target_id": target_id.to_string(), "vendor": vendor_name }),
    )
    .await?;
    tx.commit().await?;
    // Policy: iot.remote_access decides allow / require_approval / deny.
    let decision = remote_policy(&st, ctx.tenant(), &tg, vendor_id, &email, &protocol, now).await;
    let require_approval = tg["require_approval"].as_bool().unwrap_or(true);
    let mut tx = ctx.tx().await?;
    let outcome = match decision.as_deref() {
        Some("deny") => {
            sqlx::query(
                "UPDATE access_requests SET state = 'denied', decided_by = 'policy', decided_at = now(), decision_comment = 'denied by iot.remote_access policy' WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            "denied_by_policy"
        }
        Some("allow") if !require_approval => {
            tx.commit().await?;
            approve(&st, &ctx, id, "policy", Some("allowed by iot.remote_access policy")).await?;
            tx = ctx.tx().await?;
            "approved_by_policy"
        }
        _ => "pending_approval",
    };
    tx.commit().await?;
    let mut approval = None;
    if outcome == "pending_approval" && st.platform.configured() {
        let req = json!({ "kind": "iot_remote_access", "title": format!("OT remote access for {email} to {}", tg["name"].as_str().unwrap_or("")),
            "details": { "access_request_id": id, "target": tg["name"], "protocol": protocol, "window_start": start, "window_end": end, "justification": justification, "ticket": ticket, "vendor": vendor_name },
            "object_type": "iot_access_request", "object_id": id.to_string(), "requested_by": email, "requester_admin_id": requester_admin, "required_permission": "policy.iot:activate",
            "expires_in_hours": ((end - now).num_hours() + 1).clamp(1, 720) });
        match st.platform.create_approval(ctx.tenant(), &req).await {
            Ok(v) => {
                approval = v["data"]["id"].as_str().and_then(|s| Uuid::parse_str(s).ok());
                let mut tx = ctx.tx().await?;
                sqlx::query("UPDATE access_requests SET approval_id = $2 WHERE id = $1").bind(id).bind(approval).execute(&mut *tx).await?;
                tx.commit().await?;
            }
            Err(e) => tracing::warn!(error = %e, "approval inbox unavailable; the request awaits local approval"),
        }
    }
    let mut tx = ctx.tx().await?;
    let r = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Envelope::created(&ctx, json!({ "request": r, "outcome": outcome, "approval_id": approval })).location(format!("/api/v1/access-requests/{id}")))
}

/// Evaluate the tenant's active `iot.remote_access` policy (None when no
/// policy is active or the platform is unreachable).
async fn remote_policy(st: &AppState, tenant: Uuid, tg: &Value, vendor: Option<Uuid>, email: &str, protocol: &str, now: DateTime<Utc>) -> Option<String> {
    if !st.platform.configured() {
        return None;
    }
    let p = st.platform.active_policies(tenant, iot_core::policy::REMOTE_ACCESS).await.ok()?.into_iter().find(|c| c.policy_type == iot_core::policy::REMOTE_ACCESS)?;
    let mut target = iot_core::policy::DeviceCtx::default();
    if let Some(a) = tg["asset_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()) {
        let mut tx = aether_kit::db::tenant_tx(&st.pool, tenant).await.ok()?;
        target = super::segmentation::device_ctx(&mut tx, a).await.ok()?;
        tx.commit().await.ok()?;
    }
    let vendor_s = vendor.map(|v| v.to_string());
    let ctx = iot_core::policy::remote_access_context(None, &[], vendor_s.as_deref(), protocol, false, false, false, &target, now);
    let _ = email;
    Some(aether_core::policy::eval::PreparedPolicy::new(p).evaluate(&ctx, false).action)
}

/// Approve a request: grant the JIT window through the access broker.
pub async fn approve(st: &AppState, ctx: &Ctx, id: Uuid, by: &str, comment: Option<&str>) -> ApiResult<Value> {
    let mut tx = ctx.tx().await?;
    let r = load(&mut tx, id).await?;
    let state = RequestState::parse(r["state"].as_str().unwrap_or("")).unwrap_or(RequestState::Cancelled);
    if !state.can_move_to(RequestState::Approved) {
        return Err(ApiError::conflict("invalid_state", format!("the request is {}", state.as_str())));
    }
    let tg: Option<(Option<String>,)> =
        sqlx::query_as("SELECT console_id FROM remote_targets WHERE id = $1").bind(r["target_id"].as_str().and_then(|s| Uuid::parse_str(s).ok())).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    let console = tg.and_then(|t| t.0).unwrap_or_default();
    let start: DateTime<Utc> = r["window_start"].as_str().and_then(|s| s.parse().ok()).unwrap_or_else(Utc::now);
    let end: DateTime<Utc> = r["window_end"].as_str().and_then(|s| s.parse().ok()).unwrap_or_else(Utc::now);
    let email = r["requester_email"].as_str().unwrap_or_default().to_string();
    let grant = if console.is_empty() {
        crate::integrations::LocalAccess.grant_local()
    } else {
        match st.peers.private_access.grant(ctx.tenant(), &email, &console, start, end, r["justification"].as_str().unwrap_or("")).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(error = %e, "private access grant failed; recording a local JIT window");
                crate::integrations::LocalAccess.grant_local()
            }
        }
    };
    let mut tx = ctx.tx().await?;
    sqlx::query("UPDATE access_requests SET state = 'approved', decided_by = $2, decided_at = now(), decision_comment = $3, grant_ref = $4, grant_source = $5, version = version + 1, updated_at = now() WHERE id = $1 AND state = 'pending_approval'")
        .bind(id)
        .bind(by)
        .bind(comment)
        .bind(&grant.reference)
        .bind(&grant.source)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, ctx, Entry::new("approve", "access_request", Some(id)).reason(format!("by {by}; grant via {}", grant.source))).await?;
    events::emit_simple(&mut tx, ctx, "access_request", "approved", id, None, json!({ "id": id, "grant_source": grant.source })).await?;
    pipeline::log(&mut tx, ctx.tenant(), "iot_remote_access", "approve", None, None, json!({ "request_id": id.to_string(), "event": "approved", "target_id": r["target_id"] }))
        .await?;
    let out = load(&mut tx, id).await?;
    tx.commit().await?;
    Ok(out)
}

/// Close a request (deny / cancel / revoke / expire) and its sessions.
pub async fn close(st: &AppState, ctx: &Ctx, id: Uuid, to: RequestState, by: &str, comment: Option<&str>) -> ApiResult<Value> {
    let mut tx = ctx.tx().await?;
    let r = load(&mut tx, id).await?;
    let state = RequestState::parse(r["state"].as_str().unwrap_or("")).unwrap_or(RequestState::Cancelled);
    if !state.can_move_to(to) {
        return Err(ApiError::conflict("invalid_state", format!("cannot move a {} request to {}", state.as_str(), to.as_str())));
    }
    sqlx::query("UPDATE access_requests SET state = $2, decided_by = coalesce(decided_by, $3), decided_at = coalesce(decided_at, now()), decision_comment = coalesce($4, decision_comment), version = version + 1, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(to.as_str())
        .bind(by)
        .bind(comment)
        .execute(&mut *tx)
        .await?;
    let reason = if to == RequestState::Revoked { "revoked" } else { "terminated" };
    let ended = sqlx::query("UPDATE remote_sessions SET ended_at = now(), end_reason = $2 WHERE request_id = $1 AND ended_at IS NULL")
        .bind(id)
        .bind(reason)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    audit::record(&mut tx, ctx, Entry::new(to.as_str(), "access_request", Some(id)).reason(format!("by {by}; {ended} sessions ended"))).await?;
    events::emit_simple(&mut tx, ctx, "access_request", to.as_str(), id, None, json!({ "id": id, "sessions_ended": ended })).await?;
    pipeline::log(&mut tx, ctx.tenant(), "iot_remote_access", to.as_str(), None, None, json!({ "request_id": id.to_string(), "event": to.as_str(), "target_id": r["target_id"] }))
        .await?;
    let out = load(&mut tx, id).await?;
    tx.commit().await?;
    if state == RequestState::Approved {
        if let (Some(src), Some(rf)) = (r["grant_source"].as_str(), r["grant_ref"].as_str()) {
            let g = crate::integrations::Grant { source: src.into(), reference: rf.into() };
            if let Err(e) = st.peers.private_access.revoke(ctx.tenant(), &g).await {
                tracing::warn!(error = %e, "could not revoke the broker grant; it expires with its window");
            }
        }
    }
    if let (Some(a), true) = (r["approval_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()), state == RequestState::PendingApproval && st.platform.configured()) {
        let _ = st.platform.cancel_approval(ctx.tenant(), a).await;
    }
    Ok(out)
}

async fn action(State(st): State<AppState>, ctx: Ctx, Path((id, action)): Path<(Uuid, String)>, body: Option<Json<Value>>) -> ApiResult<Envelope> {
    let comment = body.as_ref().and_then(|b| b["comment"].as_str().map(|s| s.chars().take(2000).collect::<String>()));
    let by = ctx.p.name.clone();
    let out = match action.as_str() {
        "approve" => {
            pre(&ctx, ACTIVATE)?;
            let mut tx = ctx.tx().await?;
            let r = load(&mut tx, id).await?;
            tx.commit().await?;
            if ctx.p.actor_type == ActorType::Admin && r["requester_admin_id"].as_str() == Some(&ctx.p.actor_id.to_string()) {
                return Err(ApiError::forbidden("the requester cannot approve their own access request"));
            }
            approve(&st, &ctx, id, &by, comment.as_deref()).await?
        }
        "deny" => {
            pre(&ctx, ACTIVATE)?;
            close(&st, &ctx, id, RequestState::Denied, &by, comment.as_deref()).await?
        }
        "revoke" => {
            pre(&ctx, UPDATE)?;
            close(&st, &ctx, id, RequestState::Revoked, &by, comment.as_deref()).await?
        }
        "cancel" => {
            pre(&ctx, UPDATE)?;
            close(&st, &ctx, id, RequestState::Cancelled, &by, comment.as_deref()).await?
        }
        _ => return Err(ApiError::not_found("access request action")),
    };
    Ok(Envelope::ok(&ctx, out))
}

async fn start_session(ctx: Ctx, Path(id): Path<Uuid>, body: Option<Json<Value>>) -> ApiResult<Envelope> {
    pre(&ctx, CREATE)?;
    let now = Utc::now();
    let mut tx = ctx.tx().await?;
    let r = load(&mut tx, id).await?;
    let state = RequestState::parse(r["state"].as_str().unwrap_or("")).unwrap_or(RequestState::Cancelled);
    let start: DateTime<Utc> = r["window_start"].as_str().and_then(|s| s.parse().ok()).unwrap_or(now);
    let end: DateTime<Utc> = r["window_end"].as_str().and_then(|s| s.parse().ok()).unwrap_or(now);
    let until = remote::can_start(state, start, end, now).map_err(|c| ApiError::conflict(c, "the session cannot start now"))?;
    let (live,): (i64,) = sqlx::query_as("SELECT count(*) FROM remote_sessions WHERE request_id = $1 AND ended_at IS NULL").bind(id).fetch_one(&mut *tx).await?;
    if live > 0 {
        return Err(ApiError::conflict("session_active", "a session for this request is already active"));
    }
    let sid = Uuid::now_v7();
    let client_ip = body.as_ref().and_then(|b| b["client_ip"].as_str().map(String::from)).or(ctx.meta.ip.clone());
    sqlx::query("INSERT INTO remote_sessions (id, tenant_id, request_id, user_email, client_ip) VALUES ($1,$2,$3,$4,$5)")
        .bind(sid)
        .bind(ctx.tenant())
        .bind(id)
        .bind(r["requester_email"].as_str())
        .bind(&client_ip)
        .execute(&mut *tx)
        .await?;
    let tg: Option<(Value,)> = sqlx::query_as("SELECT jsonb_build_object('console_id', console_id, 'host', host, 'port', port, 'name', name) FROM remote_targets WHERE id = $1")
        .bind(r["target_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
        .fetch_optional(&mut *tx)
        .await?;
    audit::record(&mut tx, &ctx, Entry::new("start_session", "remote_session", Some(sid)).reason(format!("request {id}"))).await?;
    events::emit_simple(&mut tx, &ctx, "remote_session", "started", sid, Some(1), json!({ "id": sid, "request_id": id, "until": until })).await?;
    pipeline::log(
        &mut tx,
        ctx.tenant(),
        "iot_remote_access",
        "session_start",
        None,
        None,
        json!({ "request_id": id.to_string(), "event": "session_started", "session_id": sid.to_string(), "target_id": r["target_id"] }),
    )
    .await?;
    tx.commit().await?;
    let target = tg.map(|t| t.0).unwrap_or(json!({}));
    Ok(Envelope::created(
        &ctx,
        json!({ "session_id": sid, "request_id": id, "expires_at": until, "broker": r["grant_source"], "launch": { "console_id": target["console_id"], "target": target["name"], "grant_ref": r["grant_ref"] } }),
    ))
}

async fn sessions(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as("SELECT to_jsonb(s) FROM remote_sessions s WHERE ($1::text IS NULL OR ($1 = 'active' AND ended_at IS NULL) OR ($1 = 'ended' AND ended_at IS NOT NULL)) ORDER BY started_at DESC LIMIT $2")
        .bind(q.get("state"))
        .bind(limit(&q))
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

async fn session(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let r: Option<(Value,)> = sqlx::query_as("SELECT to_jsonb(s) FROM remote_sessions s WHERE id = $1").bind(id).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, r.ok_or_else(|| ApiError::not_found("remote session"))?.0))
}

/// End a session (used by supervision and the session's own end).
pub async fn end_session(tx: &mut aether_kit::db::Tx, ctx: &Ctx, id: Uuid, reason: &str) -> ApiResult<bool> {
    let n = sqlx::query("UPDATE remote_sessions SET ended_at = now(), end_reason = $2 WHERE id = $1 AND ended_at IS NULL")
        .bind(id)
        .bind(reason)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    if n > 0 {
        audit::record(tx, ctx, Entry::new("end_session", "remote_session", Some(id)).reason(reason.to_string())).await?;
        events::emit_simple(tx, ctx, "remote_session", "ended", id, None, json!({ "id": id, "reason": reason })).await?;
        pipeline::log(
            tx,
            ctx.tenant(),
            "iot_remote_access",
            "session_end",
            None,
            None,
            json!({ "request_id": "", "event": format!("session_ended:{reason}"), "session_id": id.to_string() }),
        )
        .await?;
    }
    Ok(n > 0)
}

async fn session_action(State(st): State<AppState>, ctx: Ctx, Path((id, action)): Path<(Uuid, String)>, body: Option<Json<Value>>) -> ApiResult<Envelope> {
    let mut tx = ctx.tx().await?;
    let r: Option<(Uuid, Option<DateTime<Utc>>, Option<String>)> =
        sqlx::query_as("SELECT request_id, ended_at, broker_session_id FROM remote_sessions WHERE id = $1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await?;
    let (req, ended, broker) = r.ok_or_else(|| ApiError::not_found("remote session"))?;
    if ended.is_some() {
        return Err(ApiError::conflict("session_ended", "the session has ended"));
    }
    let out = match action.as_str() {
        "activity" => {
            pre(&ctx, CREATE)?;
            let b = body.map(|b| b.0).unwrap_or(json!({}));
            let ev = b["event"].as_str().map(|e| json!({ "at": Utc::now(), "event": e.chars().take(200).collect::<String>() }));
            sqlx::query("UPDATE remote_sessions SET last_activity_at = now(), bytes_in = bytes_in + $2, bytes_out = bytes_out + $3, events = CASE WHEN $4::jsonb IS NULL OR jsonb_array_length(events) >= 500 THEN events ELSE events || jsonb_build_array($4::jsonb) END WHERE id = $1")
                .bind(id)
                .bind(b["bytes_in"].as_i64().unwrap_or(0).max(0))
                .bind(b["bytes_out"].as_i64().unwrap_or(0).max(0))
                .bind(ev)
                .execute(&mut *tx)
                .await?;
            json!({ "id": id, "recorded": true })
        }
        "end" => {
            pre(&ctx, CREATE)?;
            end_session(&mut tx, &ctx, id, "completed").await?;
            json!({ "id": id, "ended": true })
        }
        "terminate" => {
            pre(&ctx, UPDATE)?;
            sqlx::query("UPDATE remote_sessions SET terminate_requested = true WHERE id = $1").bind(id).execute(&mut *tx).await?;
            end_session(&mut tx, &ctx, id, "terminated").await?;
            if let Some(b) = &broker {
                if let Err(e) = st.peers.private_access.terminate(ctx.tenant(), b).await {
                    tracing::warn!(error = %e, "broker termination failed");
                }
            }
            json!({ "id": id, "terminated": true, "request_id": req })
        }
        _ => return Err(ApiError::not_found("session action")),
    };
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, out))
}

async fn recording(ctx: Ctx, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let m: RecordingMeta = serde_json::from_value(body).map_err(|e| ApiError::bad_request(format!("invalid recording metadata: {e}")))?;
    m.validate().map_err(|c| ApiError::field("sha256", c, "invalid recording metadata"))?;
    let mut tx = ctx.tx().await?;
    let n =
        sqlx::query("UPDATE remote_sessions SET recording = $2 WHERE id = $1").bind(id).bind(serde_json::to_value(&m).unwrap_or_default()).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("remote session"));
    }
    audit::record(&mut tx, &ctx, Entry::new("record", "remote_session", Some(id)).reason(format!("recording {} sha256 {}", m.recording_id, m.sha256))).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, json!({ "id": id, "recording": m })))
}
