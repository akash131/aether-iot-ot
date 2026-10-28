//! Background workers (ZTE-IOT sections 53 baseline completion, 63 feed
//! ingestion, 80 branch integration, 81 firewall bindings, 90 approvals,
//! 91 session supervision, 92 log shipping, 95 risk signals, 114 event
//! bus, 118 retention, 121 SRE health alerts, 135 lifecycle).
//!
//! Every task is idempotent and bounded per cycle; failures are logged,
//! counted and retried on the next cycle with back-off (outbox rows carry
//! attempts and the next attempt time), so a slow or unavailable
//! dependency never blocks the others.

use crate::api::remote;
use crate::pipeline;
use crate::state::AppState;
use aether_kit::{ApiError, ApiResult, Ctx};
use chrono::{DateTime, Utc};
use iot_core::model::{Observation, Signal};
use iot_core::remote::RequestState;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(state.cfg.worker_interval_ms)).await;
            tick += 1;
            if let Err(e) = run_cycle(&state, tick).await {
                state.metrics.count("worker_cycle", "error");
                tracing::warn!(error = %e.detail, "worker cycle failed");
            }
        }
    });
}

/// Tenants with product data.
pub async fn tenants(state: &AppState) -> ApiResult<Vec<Uuid>> {
    let mut tx = aether_kit::db::system_tx(&state.pool).await?;
    let rows: Vec<(Uuid,)> = sqlx::query_as("SELECT tenant_id FROM sensors UNION SELECT tenant_id FROM assets UNION SELECT tenant_id FROM access_requests UNION SELECT tenant_id FROM log_outbox UNION SELECT tenant_id FROM zones").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// One worker cycle (frequent tasks every cycle, slower ones every N).
pub async fn run_cycle(state: &AppState, tick: u64) -> ApiResult<()> {
    let started = std::time::Instant::now();
    let _ = ship_logs(state).await.map_err(|e| tracing::warn!(error = %e, "log shipping failed"));
    let _ = ship_signals(state).await.map_err(|e| tracing::warn!(error = %e, "signal shipping failed"));
    let _ = relay(state).await.map_err(|e| tracing::warn!(error = %e, "event relay failed"));
    for t in tenants(state).await? {
        let _ = supervise_remote(state, t).await.map_err(|e| tracing::warn!(error = %e.detail, "remote access supervision failed"));
        let _ = sync_approvals(state, t).await.map_err(|e| tracing::warn!(error = %e.detail, "approval sync failed"));
        if tick.is_multiple_of(6) {
            let _ = sweep(state, t).await.map_err(|e| tracing::warn!(error = %e.detail, "sweep failed"));
            let _ = sync_private_access(state, t).await.map_err(|e| tracing::warn!(error = %e.detail, "private access sync failed"));
            let _ = pull_branch(state, t).await.map_err(|e| tracing::warn!(error = %e.detail, "branch pull failed"));
            let _ = push_firewall(state, t).await.map_err(|e| tracing::warn!(error = %e.detail, "firewall binding push failed"));
            let _ = poll_revocations(state, t).await.map_err(|e| tracing::warn!(error = %e, "revocation poll failed"));
        }
        if tick.is_multiple_of(60) {
            let _ = housekeeping(state, t).await.map_err(|e| tracing::warn!(error = %e.detail, "housekeeping failed"));
        }
    }
    if tick % 17_280 == 1 && state.cfg.peers.vuln_feed_url.is_some() {
        if let Err(e) = crate::api::findings::refresh_feed(state).await {
            tracing::warn!(error = %e, "vulnerability feed refresh failed; keeping the previous feed");
        }
    }
    state.telemetry.observe("worker_cycle", started.elapsed());
    Ok(())
}

/// Ship queued log records to the platform log store. Returns the number shipped.
pub async fn ship_logs(state: &AppState) -> anyhow::Result<usize> {
    if !state.platform.configured() {
        return Ok(0);
    }
    let mut shipped = 0;
    for t in tenants(state).await.map_err(|e| anyhow::anyhow!(e.detail))? {
        loop {
            let mut tx = aether_kit::db::tenant_tx(&state.pool, t).await?;
            let rows: Vec<(i64, Value)> =
                sqlx::query_as("SELECT id, record FROM log_outbox WHERE next_attempt_at <= now() ORDER BY id LIMIT 1000 FOR UPDATE SKIP LOCKED").fetch_all(&mut *tx).await?;
            if rows.is_empty() {
                tx.commit().await?;
                break;
            }
            let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
            let recs: Vec<Value> = rows.into_iter().map(|r| r.1).collect();
            match state.platform.ingest_logs(t, &recs).await {
                Ok(v) => {
                    sqlx::query("DELETE FROM log_outbox WHERE id = ANY($1)").bind(&ids).execute(&mut *tx).await?;
                    tx.commit().await?;
                    shipped += ids.len();
                    let rejected = v["data"]["rejected"].as_array().map(|a| a.len()).unwrap_or(0);
                    if rejected > 0 {
                        state.metrics.count("log_rejected", "platform");
                        tracing::warn!(rejected, sample = %v["data"]["rejected"][0], "platform rejected log records");
                    }
                    state.metrics.count("log_shipped", "ok");
                }
                Err(e) => {
                    sqlx::query("UPDATE log_outbox SET attempts = attempts + 1, next_attempt_at = now() + make_interval(secs => least(300, 5 * power(2, least(attempts, 6)))), last_error = $2 WHERE id = ANY($1)")
                        .bind(&ids)
                        .bind(e.to_string())
                        .execute(&mut *tx)
                        .await?;
                    tx.commit().await?;
                    state.metrics.count("log_shipped", "error");
                    break;
                }
            }
        }
    }
    Ok(shipped)
}

/// Ship queued risk signals.
pub async fn ship_signals(state: &AppState) -> anyhow::Result<usize> {
    if !state.platform.configured() {
        return Ok(0);
    }
    let mut n = 0;
    for t in tenants(state).await.map_err(|e| anyhow::anyhow!(e.detail))? {
        let mut tx = aether_kit::db::tenant_tx(&state.pool, t).await?;
        let rows: Vec<(i64, Value)> =
            sqlx::query_as("SELECT id, signal FROM signal_outbox WHERE next_attempt_at <= now() ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED").fetch_all(&mut *tx).await?;
        if rows.is_empty() {
            tx.commit().await?;
            continue;
        }
        let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
        let sigs: Vec<Value> = rows.into_iter().map(|r| r.1).collect();
        match state.platform.post_signals(t, &sigs).await {
            Ok(_) => {
                sqlx::query("DELETE FROM signal_outbox WHERE id = ANY($1)").bind(&ids).execute(&mut *tx).await?;
                n += ids.len();
            }
            Err(e) => {
                sqlx::query("UPDATE signal_outbox SET attempts = attempts + 1, next_attempt_at = now() + interval '60 seconds', last_error = $2 WHERE id = ANY($1)")
                    .bind(&ids)
                    .bind(e.to_string())
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
    }
    Ok(n)
}

/// Relay the outbox (and audit) to the platform event bus.
pub async fn relay(state: &AppState) -> anyhow::Result<usize> {
    if !state.platform.configured() {
        return Ok(0);
    }
    let p = state.platform.clone();
    let stats = aether_kit::events::relay_to_platform(&state.pool, state.platform.http(), state.platform.base(), 500, move |t| {
        let p = p.clone();
        async move { p.service_token(Some(t)).await.map_err(|e| anyhow::anyhow!(e.to_string())) }
    })
    .await?;
    Ok(stats.events + stats.audit)
}

/// Poll the platform revocation feed for a tenant.
pub async fn poll_revocations(state: &AppState, tenant: Uuid) -> anyhow::Result<usize> {
    if !state.platform.configured() {
        return Ok(0);
    }
    let token = state.platform.service_token(Some(tenant)).await?;
    let feed = state.revocation_feed(tenant);
    let n = feed.poll(state.platform.http(), state.platform.base(), &token).await?;
    feed.prune(Duration::from_secs(86_400));
    Ok(n)
}

async fn get_sync(tx: &mut aether_kit::db::Tx, key: &str) -> ApiResult<Value> {
    let r: Option<(Value,)> = sqlx::query_as("SELECT value FROM sync_state WHERE key = $1").bind(key).fetch_optional(&mut **tx).await?;
    Ok(r.map(|x| x.0).unwrap_or(Value::Null))
}

async fn put_sync(tx: &mut aether_kit::db::Tx, tenant: Uuid, key: &str, v: Value) -> ApiResult<()> {
    sqlx::query("INSERT INTO sync_state (tenant_id, key, value) VALUES ($1,$2,$3) ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()")
        .bind(tenant)
        .bind(key)
        .bind(v)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn system_ctx(state: &AppState, tenant: Uuid) -> Ctx {
    Ctx::system(state.pool.clone(), crate::state::SERVICE_NAME, tenant, Uuid::now_v7().to_string())
}

/// Apply decisions from the platform approval inbox to access requests,
/// exceptions and active queries. Returns the number applied.
pub async fn sync_approvals(state: &AppState, tenant: Uuid) -> ApiResult<usize> {
    if !state.platform.configured() {
        return Ok(0);
    }
    let ctx = system_ctx(state, tenant);
    let mut tx = ctx.tx().await?;
    // Approval versions are per approval (1 = requested, 2+ = decided):
    // decided approvals are those above version 1; applying is idempotent.
    let since = 1;
    let pending: (i64,) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM access_requests WHERE state = 'pending_approval' AND approval_id IS NOT NULL) + (SELECT count(*) FROM exceptions WHERE state = 'pending_approval' AND approval_id IS NOT NULL)
             + (SELECT count(*) FROM active_queries WHERE state = 'pending_approval' AND approval_id IS NOT NULL)",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    if pending.0 == 0 {
        return Ok(0);
    }
    let v = state.platform.decided_approvals(tenant, since).await.map_err(|e| ApiError::unavailable(e.to_string()))?;
    let mut applied = 0;
    for a in v["data"].as_array().cloned().unwrap_or_default() {
        let Some(aid) = a["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()) else { continue };
        let st = a["state"].as_str().unwrap_or("");
        let by = a["decided_by_name"].as_str().unwrap_or("approver").to_string();
        let comment = a["decision_comment"].as_str().map(String::from);
        let mut tx = ctx.tx().await?;
        let req: Option<(Uuid, String)> = sqlx::query_as("SELECT id, state FROM access_requests WHERE approval_id = $1").bind(aid).fetch_optional(&mut *tx).await?;
        let exc: Option<(Uuid, String)> = sqlx::query_as("SELECT id, state FROM exceptions WHERE approval_id = $1").bind(aid).fetch_optional(&mut *tx).await?;
        let aq: Option<(Uuid, String)> = sqlx::query_as("SELECT id, state FROM active_queries WHERE approval_id = $1").bind(aid).fetch_optional(&mut *tx).await?;
        if let Some((eid, s)) = &exc {
            if s == "pending_approval" && (st == "approved" || st == "denied") {
                crate::api::segmentation::decide_exception(&mut tx, &ctx, *eid, if st == "approved" { "approve" } else { "deny" }, &by).await?;
                applied += 1;
            }
        }
        if let Some((qid, s)) = &aq {
            if s == "pending_approval" {
                sqlx::query("UPDATE active_queries SET state = $2, updated_at = now() WHERE id = $1")
                    .bind(qid)
                    .bind(if st == "approved" { "approved" } else { "cancelled" })
                    .execute(&mut *tx)
                    .await?;
                applied += 1;
            }
        }
        tx.commit().await?;
        if let Some((rid, s)) = req {
            if s == "pending_approval" {
                match st {
                    "approved" => {
                        remote::approve(state, &ctx, rid, &by, comment.as_deref()).await?;
                    }
                    "denied" => {
                        remote::close(state, &ctx, rid, RequestState::Denied, &by, comment.as_deref()).await?;
                    }
                    "expired" => {
                        remote::close(state, &ctx, rid, RequestState::Expired, "approval expired", None).await?;
                    }
                    _ => continue,
                }
                applied += 1;
            }
        }
    }
    let mut tx = ctx.tx().await?;
    put_sync(&mut tx, tenant, "approvals_synced_at", json!(Utc::now())).await?;
    tx.commit().await?;
    // Direct look-ups for requests whose approval is not in the page yet.
    let mut tx = ctx.tx().await?;
    let open: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, approval_id FROM access_requests WHERE state = 'pending_approval' AND approval_id IS NOT NULL LIMIT 50").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    for (rid, aid) in open {
        if let Ok(v) = state.platform.get_approval(tenant, aid).await {
            let st = v["data"]["state"].as_str().unwrap_or("");
            let by = v["data"]["decided_by_name"].as_str().unwrap_or("approver").to_string();
            match st {
                "approved" => {
                    remote::approve(state, &ctx, rid, &by, v["data"]["decision_comment"].as_str()).await?;
                    applied += 1;
                }
                "denied" => {
                    remote::close(state, &ctx, rid, RequestState::Denied, &by, v["data"]["decision_comment"].as_str()).await?;
                    applied += 1;
                }
                "expired" | "cancelled" => {
                    remote::close(state, &ctx, rid, RequestState::Expired, "approval expired", None).await?;
                    applied += 1;
                }
                _ => {}
            }
        }
    }
    Ok(applied)
}

/// End sessions that must end; expire requests and exceptions.
pub async fn supervise_remote(state: &AppState, tenant: Uuid) -> ApiResult<usize> {
    let ctx = system_ctx(state, tenant);
    let now = Utc::now();
    let mut tx = ctx.tx().await?;
    let lim = remote::limits(&mut tx).await?;
    let live: Vec<(Uuid, String, DateTime<Utc>, DateTime<Utc>, DateTime<Utc>, bool)> = sqlx::query_as(
        "SELECT s.id, r.state, r.window_end, s.started_at, s.last_activity_at, s.terminate_requested FROM remote_sessions s JOIN access_requests r ON r.id = s.request_id WHERE s.ended_at IS NULL",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut ended = 0;
    for (sid, st, wend, started, last, term) in live {
        let state_ = RequestState::parse(&st).unwrap_or(RequestState::Revoked);
        if let Some(reason) = iot_core::remote::must_end(state_, wend, started, last, term, &lim, now) {
            if remote::end_session(&mut tx, &ctx, sid, reason.as_str()).await? {
                ended += 1;
            }
        }
    }
    let expired: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM access_requests WHERE (state = 'approved' AND window_end <= now()) OR (state = 'pending_approval' AND window_end <= now())")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    for (rid,) in expired {
        let mut tx = ctx.tx().await?;
        let s: (String,) = sqlx::query_as("SELECT state FROM access_requests WHERE id = $1").bind(rid).fetch_one(&mut *tx).await?;
        let (used,): (i64,) = sqlx::query_as("SELECT count(*) FROM remote_sessions WHERE request_id = $1").bind(rid).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        let to = if s.0 == "approved" && used > 0 { RequestState::Completed } else { RequestState::Expired };
        let _ = remote::close(state, &ctx, rid, to, "window ended", None).await;
    }
    let mut tx = ctx.tx().await?;
    let n =
        sqlx::query("UPDATE exceptions SET state = 'expired', version = version + 1, updated_at = now() WHERE state IN ('approved','pending_approval') AND expires_at <= now()")
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if n > 0 {
        aether_kit::events::emit_simple(&mut tx, &ctx, "exception", "expired", "batch", None, json!({ "count": n })).await?;
    }
    sqlx::query("UPDATE vendor_principals SET enabled = false, version = version + 1, updated_at = now() WHERE enabled AND expires_at <= now() AND deleted_at IS NULL")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ended)
}

/// Read broker sessions and recording metadata for approved requests.
pub async fn sync_private_access(state: &AppState, tenant: Uuid) -> ApiResult<usize> {
    if !state.peers.private_access.configured() {
        return Ok(0);
    }
    let ctx = system_ctx(state, tenant);
    let mut tx = ctx.tx().await?;
    let reqs: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT r.id, t.console_id, r.requester_email FROM access_requests r JOIN remote_targets t ON t.id = r.target_id WHERE r.grant_source = 'private_access' AND t.console_id IS NOT NULL AND r.state IN ('approved','completed') AND r.window_end > now() - interval '1 day'",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut n = 0;
    for (rid, console, email) in reqs {
        let sessions = match state.peers.private_access.sessions(tenant, &console).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "broker sessions unavailable");
                continue;
            }
        };
        let mut tx = ctx.tx().await?;
        for s in sessions.into_iter().filter(|s| s.user.eq_ignore_ascii_case(&email)) {
            let r = sqlx::query(
                "INSERT INTO remote_sessions (id, tenant_id, request_id, user_email, started_at, ended_at, end_reason, broker_session_id, recording)
                 SELECT $1,$2,$3,$4,coalesce($5, now()),$6,CASE WHEN $6 IS NULL THEN NULL ELSE 'completed' END,$7,$8
                 WHERE NOT EXISTS (SELECT 1 FROM remote_sessions WHERE broker_session_id = $7)",
            )
            .bind(Uuid::now_v7())
            .bind(tenant)
            .bind(rid)
            .bind(&s.user)
            .bind(s.started_at)
            .bind(s.ended_at)
            .bind(&s.id)
            .bind(&s.recording)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE remote_sessions SET recording = coalesce($2, recording), ended_at = coalesce(ended_at, $3) WHERE broker_session_id = $1")
                .bind(&s.id)
                .bind(&s.recording)
                .bind(s.ended_at)
                .execute(&mut *tx)
                .await?;
            n += r.rows_affected() as usize;
        }
        tx.commit().await?;
    }
    Ok(n)
}

/// Pull device observations from Aether Branch as integration assertions.
pub async fn pull_branch(state: &AppState, tenant: Uuid) -> ApiResult<usize> {
    if !state.peers.branch.configured() {
        return Ok(0);
    }
    let ctx = system_ctx(state, tenant);
    let mut tx = ctx.tx().await?;
    let cursor = get_sync(&mut tx, "branch_cursor").await?.as_str().map(String::from);
    let sites: Vec<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id, branch_site_id FROM sites WHERE deleted_at IS NULL AND branch_site_id IS NOT NULL").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let (devices, next) = state.peers.branch.devices(tenant, cursor.clone()).await.map_err(|e| ApiError::unavailable(e.to_string()))?;
    let now = Utc::now();
    let mut obs = vec![];
    for d in &devices {
        let mut o = Observation::new(d.last_seen.unwrap_or(now).min(now), Some(&d.mac), d.ip.as_deref());
        o.passive = true;
        o.site = d.site_id.as_ref().and_then(|bs| sites.iter().find(|(_, b)| b.as_deref() == Some(bs.as_str()))).map(|(s, _)| s.to_string());
        o.signals.push(Signal::Asserted {
            source: "branch".into(),
            device_type: d.class.as_deref().and_then(crate::integrations::branch_class).map(String::from),
            vendor: d.vendor.clone(),
            model: None,
            os: d.os.clone(),
            firmware: None,
            hostname: d.hostname.clone(),
            confidence: d.confidence.unwrap_or(0.5),
        });
        obs.push(o);
    }
    let n = obs.len();
    if n > 0 {
        let tc = pipeline::tenant_ctx(state, tenant).await?;
        for mut o in obs {
            if o.sanitize(now).is_err() {
                continue;
            }
            let mut tx = ctx.tx().await?;
            match pipeline::process(state, &ctx, &mut tx, &tc, &o, None, Some("branch")).await {
                Ok(_) => tx.commit().await?,
                Err(e) => {
                    let _ = tx.rollback().await;
                    tracing::debug!(error = %e.detail, "branch observation rejected");
                }
            }
        }
    }
    let mut tx = ctx.tx().await?;
    put_sync(&mut tx, tenant, "branch_cursor", next.map(Value::from).unwrap_or(Value::Null)).await?;
    put_sync(&mut tx, tenant, "branch_last_pull", json!({ "at": now, "devices": n })).await?;
    tx.commit().await?;
    Ok(n)
}

/// Publish device identities to the firewall (identity bindings).
pub async fn push_firewall(state: &AppState, tenant: Uuid) -> ApiResult<usize> {
    if !state.peers.firewall.configured() {
        return Ok(0);
    }
    let ctx = system_ctx(state, tenant);
    let mut tx = ctx.tx().await?;
    let since = get_sync(&mut tx, "firewall_pushed_at").await?.as_str().and_then(|s| s.parse::<DateTime<Utc>>().ok()).unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    let rows: Vec<(String, Uuid)> =
        sqlx::query_as("SELECT ip, id FROM assets WHERE ip IS NOT NULL AND merged_into IS NULL AND lifecycle <> 'decommissioned' AND updated_at > $1 LIMIT 10000")
            .bind(since)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    let now = Utc::now();
    let n = state.peers.firewall.bind(tenant, &rows).await.map_err(|e| ApiError::unavailable(e.to_string()))?;
    let mut tx = ctx.tx().await?;
    put_sync(&mut tx, tenant, "firewall_pushed_at", json!(now)).await?;
    tx.commit().await?;
    Ok(n)
}

/// Periodic sweep: configuration changes, learning completion, inactivity,
/// assertions and health alerts.
pub async fn sweep(state: &AppState, tenant: Uuid) -> ApiResult<usize> {
    let ctx = system_ctx(state, tenant);
    let mut tx = ctx.tx().await?;
    let (cfg_mark,): (Option<DateTime<Utc>>,) = sqlx::query_as(
        "SELECT greatest((SELECT max(updated_at) FROM classification_rules), (SELECT max(updated_at) FROM device_groups), (SELECT max(updated_at) FROM zones), (SELECT max(updated_at) FROM settings))",
    )
    .fetch_one(&mut *tx)
    .await?;
    let seen = get_sync(&mut tx, "config_mark").await?.as_str().and_then(|s| s.parse::<DateTime<Utc>>().ok());
    let changed = cfg_mark.is_some() && cfg_mark != seen;
    let learning: pipeline::TenantCtx = {
        tx.commit().await?;
        pipeline::tenant_ctx(state, tenant).await?
    };
    let mut tx = ctx.tx().await?;
    let mut ids: Vec<Uuid> = if changed {
        state.invalidate(tenant);
        sqlx::query_as::<_, (Uuid,)>("SELECT id FROM assets WHERE merged_into IS NULL AND deleted_at IS NULL AND lifecycle <> 'decommissioned' LIMIT 5000")
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|r| r.0)
            .collect()
    } else {
        vec![]
    };
    // Learning windows that may complete without new traffic.
    let due: Vec<(Uuid,)> =
        sqlx::query_as("SELECT asset_id FROM baselines WHERE network_mode = 'learning' AND (data->>'started_at')::timestamptz < now() - make_interval(hours => $1) LIMIT 500")
            .bind(learning.learning.min_hours as i32)
            .fetch_all(&mut *tx)
            .await?;
    ids.extend(due.into_iter().map(|d| d.0));
    ids.sort();
    ids.dedup();
    let inactive_days = pipeline::settings(&mut tx, "retention").await?["inactive_days"].as_i64().unwrap_or(7);
    let inactive = pipeline::mark_inactive(&mut tx, inactive_days).await?;
    if changed {
        put_sync(&mut tx, tenant, "config_mark", json!(cfg_mark)).await?;
    }
    let _ = crate::api::ops::evaluate_assertions(&mut tx, tenant).await?;
    let (h, active) = crate::api::ops::health(state, &mut tx, tenant).await?;
    let _ = h;
    for a in active.as_array().cloned().unwrap_or_default() {
        let key = a["mode"]["key"].as_str().unwrap_or("");
        if let Some(m) = iot_core::failure::mode(key) {
            pipeline::raise_alert(&mut tx, tenant, m.alert, &format!("{}:tenant", m.alert), m.severity as i32, m.label, json!({ "measured": a["measured"], "guidance": m }))
                .await?;
        }
    }
    tx.commit().await?;
    let n = if ids.is_empty() { 0 } else { pipeline::reevaluate(state, tenant, &ids).await? };
    state.graph_built.insert(tenant, Utc::now());
    let _ = inactive;
    Ok(n)
}

/// Retention and learned rules.
pub async fn housekeeping(state: &AppState, tenant: Uuid) -> ApiResult<u64> {
    let ctx = system_ctx(state, tenant);
    let mut tx = ctx.tx().await?;
    sqlx::query("SELECT set_config('app.retention_purge', 'on', true)").execute(&mut *tx).await?;
    let r = pipeline::settings(&mut tx, "retention").await?;
    let obs_days = r["observation_days"].as_i64().unwrap_or(state.cfg.observation_retention_days).clamp(1, 365) as i32;
    let hist_days = r["history_days"].as_i64().unwrap_or(state.cfg.history_retention_days).clamp(30, 3650) as i32;
    let mut n = 0;
    n += sqlx::query("DELETE FROM observations WHERE received_at < now() - make_interval(days => $1)").bind(obs_days).execute(&mut *tx).await?.rows_affected();
    for (table, col) in [
        ("asset_changes", "at"),
        ("classification_history", "at"),
        ("risk_history", "at"),
        ("flow_rollups", "bucket"),
        ("protocol_stats", "bucket"),
        ("decision_stats", "bucket"),
        ("baseline_snapshots", "taken_at"),
    ] {
        n += sqlx::query(&format!("DELETE FROM {table} WHERE {col} < now() - make_interval(days => $1)")).bind(hist_days).execute(&mut *tx).await?.rows_affected();
    }
    n += sqlx::query("DELETE FROM graph_edges WHERE last_seen < now() - make_interval(days => $1)").bind(hist_days).execute(&mut *tx).await?.rows_affected();
    n += sqlx::query("DELETE FROM ingest_batches WHERE received_at < now() - interval '7 days'").execute(&mut *tx).await?.rows_affected();
    n += sqlx::query("DELETE FROM log_outbox WHERE created_at < now() - interval '7 days' AND attempts > 50").execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    let _ = crate::api::ops::learn_rules(state, tenant).await?;
    Ok(n)
}
