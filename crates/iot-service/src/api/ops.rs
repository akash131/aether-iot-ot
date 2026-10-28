//! Operations, analytics and evidence APIs (ZTE-IOT sections 54–57 graphs,
//! 98 dashboards, 104 Investigation UI, 105 Search And Reporting, 109
//! Event Apis, 110 Data Schemas, 118 Privacy, 120 Observability, 121 SRE,
//! 128–130 validation, 132 Incident Response, 133 Forensics And Evidence,
//! 134 Support Diagnostics; AE-IOT-0011 assertions, AE-IOT-0034 topology
//! export).

use super::common::{limit, pre, q_uuid};
use crate::pipeline;
use crate::state::{AppState, CREATE, DELETE, READ, UPDATE};
use aether_kit::audit::{self, Entry};
use aether_kit::{events, ApiError, ApiResult, Ctx, Envelope};
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use iot_core::graph::{Graph, Node};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/graph", get(graph))
        .route("/api/v1/graph/dependencies", get(dependencies))
        .route("/api/v1/dashboards/{name}", get(dashboard))
        .route("/api/v1/search", get(search))
        .route("/api/v1/reports/{kind}", get(report))
        .route("/api/v1/status", get(status))
        .route("/api/v1/failure-modes", get(failure_modes))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/schemas", get(schemas))
        .route("/api/v1/taxonomy", get(taxonomy))
        .route("/api/v1/protocols", get(protocols))
        .route("/api/v1/integrations", get(integrations))
        .route("/api/v1/diagnostics", get(diagnostics))
        .route("/api/v1/events", get(events_list))
        .route("/api/v1/assertions/run", post(run_assertions))
        .route("/api/v1/assertions/{id}/violations", get(violations))
        .route("/api/v1/acceptance/runs", get(acceptance_runs).post(acceptance_run))
        .route("/api/v1/acceptance/runs/{id}", get(acceptance_get))
        .route("/api/v1/investigations/{id}/evidence", get(evidence_list).post(evidence_add))
        .route("/api/v1/investigations/{id}/timeline", get(investigation_timeline))
        .route("/api/v1/classification/learn", post(learn))
        .route("/api/v1/privacy/erase", post(erase))
}

/// The tenant graph (asset nodes with zones; external peers by address).
pub async fn load_graph(tx: &mut aether_kit::db::Tx, max: i64) -> ApiResult<Graph> {
    let mut g = Graph::default();
    let nodes: Vec<(Uuid, Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT a.id, coalesce(a.name, a.hostname, a.ip, a.mac), a.device_type, z.key FROM assets a LEFT JOIN zones z ON z.id = a.zone_id WHERE a.merged_into IS NULL AND a.deleted_at IS NULL LIMIT $1",
    )
    .bind(max)
    .fetch_all(&mut **tx)
    .await?;
    for (id, label, ty, zone) in nodes {
        g.add_node(Node { id: id.to_string(), label: label.unwrap_or_else(|| id.to_string()), device_type: Some(ty), zone, external: false });
    }
    let edges: Vec<(String, String, Vec<String>, Vec<i32>, Option<String>, i64)> =
        sqlx::query_as("SELECT from_node, to_node, protocols, ports, max_op, bytes FROM graph_edges ORDER BY last_seen DESC LIMIT $1").bind(max).fetch_all(&mut **tx).await?;
    for (from, to, protos, ports, op, bytes) in edges {
        let op = op.as_deref().and_then(iot_core::segmentation::op_class);
        let ports = if ports.is_empty() { vec![0] } else { ports };
        for (i, p) in ports.iter().enumerate() {
            g.add_edge(&from, &to, protos.first().map(|s| s.as_str()), *p as u16, op, if i == 0 { bytes as u64 } else { 0 });
        }
        for pr in protos.iter().skip(1) {
            g.add_edge(&from, &to, Some(pr), ports[0] as u16, op, 0);
        }
    }
    Ok(g)
}

async fn graph(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let g = load_graph(&mut tx, limit(&q).max(1000) * 10).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, json!({ "nodes": g.nodes.values().collect::<Vec<_>>(), "edges": g.edges.values().collect::<Vec<_>>(), "conduits": g.conduits() })))
}

async fn dependencies(State(st): State<AppState>, ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let id = q_uuid(&q, "asset_id")?.ok_or_else(|| ApiError::field("asset_id", "required", "asset id"))?;
    let depth = q.get("depth").and_then(|d| d.parse().ok()).unwrap_or(3usize);
    let mut tx = ctx.tx().await?;
    let g = load_graph(&mut tx, 200_000).await?;
    tx.commit().await?;
    let key = id.to_string();
    let lag = st.graph_built.get(&ctx.tenant()).map(|t| (chrono::Utc::now() - *t).num_seconds());
    Ok(Envelope::ok(
        &ctx,
        json!({ "asset_id": id, "dependencies": g.dependencies(&key, depth), "dependents": g.dependents(&key, depth), "internet_destinations": g.internet_destinations(&key), "graph_age_secs": lag }),
    ))
}

async fn dashboard(ctx: Ctx, Path(name): Path<String>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let sql = match name.as_str() {
        "overview" => {
            "SELECT jsonb_build_object(
                'assets', (SELECT count(*) FROM assets WHERE merged_into IS NULL AND deleted_at IS NULL AND lifecycle <> 'decommissioned'),
                'ot_assets', (SELECT count(*) FROM assets WHERE merged_into IS NULL AND category IN ('industrial_control','building_management','medical','physical_access')),
                'new_last_24h', (SELECT count(*) FROM assets WHERE first_seen > now() - interval '24 hours'),
                'unknown', (SELECT count(*) FROM assets WHERE device_type = 'unknown' AND merged_into IS NULL),
                'high_risk', (SELECT count(*) FROM assets WHERE risk_level IN ('high','critical') AND merged_into IS NULL),
                'quarantined', (SELECT count(*) FROM assets WHERE quarantined),
                'open_anomalies', (SELECT count(*) FROM anomalies WHERE status = 'open'),
                'open_findings', (SELECT count(*) FROM findings WHERE status = 'open'),
                'active_sessions', (SELECT count(*) FROM remote_sessions WHERE ended_at IS NULL),
                'sensors', (SELECT count(*) FROM sensors WHERE deleted_at IS NULL),
                'sensors_offline', (SELECT count(*) FROM sensors WHERE deleted_at IS NULL AND (last_seen_at IS NULL OR last_seen_at < now() - interval '5 minutes')),
                'top_risk', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, coalesce(name, hostname, ip, mac) AS name, device_type, risk_score, risk_level, priority FROM assets WHERE merged_into IS NULL ORDER BY priority DESC LIMIT 10) x),
                'recent_anomalies', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, asset_id, kind, severity, title, last_seen FROM anomalies WHERE status = 'open' ORDER BY last_seen DESC LIMIT 10) x),
                'by_category', (SELECT coalesce(jsonb_object_agg(category, n), '{}') FROM (SELECT category, count(*) n FROM assets WHERE merged_into IS NULL GROUP BY 1) x))"
        }
        "risk" => {
            "SELECT jsonb_build_object(
                'by_level', (SELECT coalesce(jsonb_object_agg(risk_level, n), '{}') FROM (SELECT risk_level, count(*) n FROM assets WHERE merged_into IS NULL GROUP BY 1) x),
                'findings_by_kind', (SELECT coalesce(jsonb_object_agg(kind, n), '{}') FROM (SELECT kind, count(*) n FROM findings WHERE status = 'open' GROUP BY 1) x),
                'known_exploited', (SELECT count(*) FROM findings WHERE status = 'open' AND known_exploited),
                'end_of_life', (SELECT count(*) FROM findings WHERE status = 'open' AND kind = 'end_of_life'),
                'priority_queue', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, coalesce(name, hostname, ip, mac) AS name, device_type, risk_score, impact, priority FROM assets WHERE merged_into IS NULL ORDER BY priority DESC LIMIT 25) x),
                'trend', (SELECT coalesce(jsonb_agg(x ORDER BY day), '[]') FROM (SELECT date_trunc('day', at) AS day, round(avg(score)) AS avg_score, count(*) AS changes FROM risk_history WHERE at > now() - interval '30 days' GROUP BY 1) x))"
        }
        "ot-activity" => {
            "SELECT jsonb_build_object(
                'protocols', (SELECT coalesce(jsonb_object_agg(protocol, n), '{}') FROM (SELECT protocol, sum(events) n FROM protocol_stats WHERE bucket > now() - interval '24 hours' GROUP BY 1) x),
                'parser_errors', (SELECT coalesce(sum(errors), 0) FROM protocol_stats WHERE bucket > now() - interval '24 hours'),
                'modifying_flows', (SELECT count(*) FROM flow_rollups WHERE bucket > now() - interval '24 hours' AND max_op IN ('write','control','program','firmware')),
                'engineering_operations', (SELECT count(*) FROM anomalies WHERE kind IN ('engineering_operation','controller_mode_change','firmware_operation') AND last_seen > now() - interval '7 days'),
                'conduits', (SELECT count(*) FROM graph_edges),
                'decisions', (SELECT coalesce(jsonb_object_agg(enforced, n), '{}') FROM (SELECT enforced, sum(count) n FROM decision_stats WHERE bucket > now() - interval '24 hours' GROUP BY 1) x))"
        }
        "remote-access" => {
            "SELECT jsonb_build_object(
                'pending', (SELECT count(*) FROM access_requests WHERE state = 'pending_approval'),
                'approved_windows', (SELECT count(*) FROM access_requests WHERE state = 'approved' AND window_end > now()),
                'active_sessions', (SELECT count(*) FROM remote_sessions WHERE ended_at IS NULL),
                'sessions_7d', (SELECT count(*) FROM remote_sessions WHERE started_at > now() - interval '7 days'),
                'vendors_expiring', (SELECT count(*) FROM vendor_principals WHERE deleted_at IS NULL AND expires_at < now() + interval '14 days'),
                'recent', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, requester_email, state, window_start, window_end FROM access_requests ORDER BY created_at DESC LIMIT 10) x))"
        }
        _ => return Err(ApiError::not_found("dashboard")),
    };
    let (v,): (Value,) = sqlx::query_as(sql).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, v))
}

async fn search(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let term = q.get("q").map(|s| s.trim()).filter(|s| s.len() >= 2 && s.len() <= 200).ok_or_else(|| ApiError::field("q", "invalid", "2..200 characters"))?;
    let like = format!("%{}%", term.replace(['%', '_'], ""));
    let mut tx = ctx.tx().await?;
    let (v,): (Value,) = sqlx::query_as(
        "SELECT jsonb_build_object(
            'assets', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, coalesce(name, hostname, ip, mac) AS name, device_type, ip, mac FROM assets WHERE merged_into IS NULL AND (hostname ILIKE $1 OR ip ILIKE $1 OR mac ILIKE $1 OR vendor ILIKE $1 OR model ILIKE $1 OR name ILIKE $1 OR serial ILIKE $1) LIMIT 25) x),
            'anomalies', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, asset_id, kind, title FROM anomalies WHERE title ILIKE $1 ORDER BY last_seen DESC LIMIT 25) x),
            'findings', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, asset_id, kind, title FROM findings WHERE title ILIKE $1 OR key ILIKE $1 LIMIT 25) x),
            'investigations', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, name, status FROM investigations WHERE deleted_at IS NULL AND (name ILIKE $1 OR description ILIKE $1) LIMIT 25) x),
            'sites', (SELECT coalesce(jsonb_agg(x), '[]') FROM (SELECT id, name FROM sites WHERE deleted_at IS NULL AND name ILIKE $1 LIMIT 25) x))",
    )
    .bind(&like)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, v))
}

const REPORTS: &[(&str, &str)] = &[
    ("inventory", "SELECT jsonb_build_object('id', id, 'name', coalesce(name, hostname, ip, mac), 'site_id', site_id, 'device_type', device_type, 'category', category, 'vendor', vendor, 'model', model, 'firmware', firmware, 'confidence', confidence, 'risk_score', risk_score, 'lifecycle', lifecycle, 'last_seen', last_seen) FROM assets WHERE merged_into IS NULL AND deleted_at IS NULL ORDER BY category, device_type, id LIMIT 100000"),
    ("risk", "SELECT jsonb_build_object('id', id, 'name', coalesce(name, hostname, ip, mac), 'device_type', device_type, 'risk_score', risk_score, 'risk_level', risk_level, 'impact', impact, 'priority', priority, 'factors', risk->'factors') FROM assets WHERE merged_into IS NULL ORDER BY priority DESC LIMIT 100000"),
    ("vulnerabilities", "SELECT jsonb_build_object('asset_id', f.asset_id, 'asset', coalesce(a.name, a.hostname, a.ip, a.mac), 'kind', f.kind, 'key', f.key, 'title', f.title, 'severity', f.severity, 'known_exploited', f.known_exploited, 'status', f.status, 'first_seen', f.first_seen) FROM findings f JOIN assets a ON a.id = f.asset_id ORDER BY f.severity DESC LIMIT 100000"),
    ("anomalies", "SELECT jsonb_build_object('asset_id', asset_id, 'kind', kind, 'severity', severity, 'title', title, 'status', status, 'count', count, 'first_seen', first_seen, 'last_seen', last_seen) FROM anomalies ORDER BY last_seen DESC LIMIT 100000"),
    ("remote_access", "SELECT jsonb_build_object('request_id', r.id, 'requester', r.requester_email, 'target_id', r.target_id, 'state', r.state, 'window_start', r.window_start, 'window_end', r.window_end, 'decided_by', r.decided_by, 'sessions', (SELECT count(*) FROM remote_sessions s WHERE s.request_id = r.id)) FROM access_requests r ORDER BY r.created_at DESC LIMIT 100000"),
    ("segmentation", "SELECT jsonb_build_object('zone', coalesce(z.key, 'unassigned'), 'security_level', z.security_level, 'mode', z.mode, 'devices', count(a.id), 'quarantined', count(a.id) FILTER (WHERE a.quarantined), 'low_confidence', count(a.id) FILTER (WHERE a.tier = 'low')) FROM assets a LEFT JOIN zones z ON z.id = a.zone_id WHERE a.merged_into IS NULL GROUP BY z.key, z.security_level, z.mode ORDER BY 1"),
];

async fn report(ctx: Ctx, Path(kind): Path<String>, Query(q): Query<HashMap<String, String>>) -> ApiResult<Response> {
    pre(&ctx, READ)?;
    let sql = REPORTS.iter().find(|r| r.0 == kind).map(|r| r.1).ok_or_else(|| ApiError::not_found("report"))?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as(sql).fetch_all(&mut *tx).await?;
    audit::record(&mut tx, &ctx, Entry::new("report", &kind, None::<Uuid>).reason(format!("{} rows", rows.len()))).await?;
    tx.commit().await?;
    let rows: Vec<Value> = rows.into_iter().map(|r| r.0).collect();
    if q.get("format").map(|f| f == "csv").unwrap_or(false) {
        let cols: Vec<String> = rows.first().and_then(|r| r.as_object()).map(|o| o.keys().cloned().collect()).unwrap_or_default();
        let mut out = cols.join(",");
        out.push('\n');
        for r in &rows {
            out.push_str(
                &cols
                    .iter()
                    .map(|c| {
                        let s = match &r[c] {
                            Value::Null => String::new(),
                            Value::String(s) => s.clone(),
                            o => o.to_string(),
                        };
                        let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s };
                        format!("\"{}\"", s.replace('"', "\"\""))
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            );
            out.push('\n');
        }
        return Ok(([(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")], out).into_response());
    }
    Ok(Envelope::ok(&ctx, json!({ "report": kind, "generated_at": chrono::Utc::now(), "rows": rows })).into_response())
}

/// Tenant health: failure modes evaluated from sensors, node reports,
/// queues, graph and feed freshness.
pub async fn health(st: &AppState, tx: &mut aether_kit::db::Tx, tenant: Uuid) -> ApiResult<(iot_core::failure::Health, Value)> {
    let (silent, policy_age, backlog, ambiguous, randomized, ipchg, parse_err): (Option<i64>, Option<i64>, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT max(extract(epoch FROM now() - last_seen_at))::bigint FROM sensors WHERE deleted_at IS NULL AND last_seen_at IS NOT NULL),
                (SELECT max((status->>'config_age_secs')::bigint) FROM node_status WHERE last_report > now() - interval '1 hour'),
                (SELECT count(*) FROM log_outbox),
                (SELECT count(*) FROM assets WHERE merged_into IS NULL AND lifecycle = 'active' AND (tier = 'low' OR jsonb_array_length(coalesce(classification->'conflicts', '[]')) > 0)),
                (SELECT count(*) FROM assets WHERE randomized_mac AND first_seen > now() - interval '1 hour'),
                (SELECT count(*) FROM asset_changes WHERE kind = 'ip_changed' AND at > now() - interval '1 hour'),
                (SELECT coalesce(sum(errors), 0)::bigint FROM protocol_stats WHERE bucket > now() - interval '1 hour')",
    )
    .fetch_one(&mut **tx)
    .await?;
    let thresholds: iot_core::failure::Thresholds = serde_json::from_value(pipeline::settings(tx, "health_thresholds").await?).unwrap_or_default();
    let graph_age = st.graph_built.get(&tenant).map(|t| (chrono::Utc::now() - *t).num_seconds());
    let h = iot_core::failure::Health {
        sensor_silent_secs: silent,
        capture_drop_ratio: 0.0,
        duplicate_ratio: 0.0,
        ip_changes_last_hour: ipchg as u64,
        randomized_macs_last_hour: randomized as u64,
        ambiguous_devices: ambiguous as u64,
        parser_failures: 0,
        malformed_per_minute: parse_err as f64 / 60.0,
        branch_reachable: true,
        policy_age_secs: policy_age,
        graph_age_secs: graph_age,
        risk_feed_age_secs: Some(st.feed_age_secs()),
        cloud_reachable: true,
        clock_skew_secs: 0,
        backlog_pct: ((backlog as f64 / 100_000.0) * 100.0).min(100.0) as u8,
        upgrade_interrupted: false,
    };
    let active = iot_core::failure::evaluate(&h, &thresholds);
    Ok((h, json!(active)))
}

async fn status(State(st): State<AppState>, ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let (h, active) = health(&st, &mut tx, ctx.tenant()).await?;
    let nodes: Vec<(Value,)> = sqlx::query_as("SELECT jsonb_build_object('node_id', node_id, 'sensor_id', sensor_id, 'last_report', last_report, 'software_version', software_version, 'config_revision', config_revision, 'status', status) FROM node_status ORDER BY last_report DESC LIMIT 500")
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Envelope::ok(
        &ctx,
        json!({ "service": crate::state::SERVICE_NAME, "version": env!("CARGO_PKG_VERSION"), "uptime_secs": st.started.elapsed().as_secs(), "platform": st.platform.health(), "integrations": st.peers.status(),
            "health": h, "active_failures": active, "nodes": nodes.into_iter().map(|n| n.0).collect::<Vec<_>>(),
            "versions": { "classifier": iot_core::classify::CLASSIFIER_VERSION, "risk_model": iot_core::risk::RISK_MODEL_VERSION, "feed": st.feed().version() } }),
    ))
}

async fn failure_modes(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    Ok(Envelope::ok(&ctx, json!({ "modes": iot_core::failure::MODES, "thresholds": iot_core::failure::Thresholds::default() })))
}

async fn capabilities(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let items: Vec<Value> = iot_core::capabilities::CAPABILITIES
        .iter()
        .map(|c| {
            let (trusted, untrusted) = c.component.inputs();
            json!({ "section": c.section, "name": c.name, "component": c.component, "modules": c.modules, "trusted_inputs": trusted, "untrusted_inputs": untrusted, "outputs": c.component.outputs(),
                "authoritative_state": c.component.state(), "trust_boundary": c.component.trust_boundary(), "acceptance_profile": c.profile, "acceptance_scenarios": iot_core::acceptance::SCENARIOS })
        })
        .collect();
    Ok(Envelope::ok(&ctx, items))
}

async fn schemas(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    Ok(Envelope::ok(
        &ctx,
        json!({ "entities": iot_core::schemas::ENTITIES, "log_types": pipeline::log_schemas().into_iter().map(|(t, f)| json!({ "log_type": t, "fields": f })).collect::<Vec<_>>() }),
    ))
}

async fn taxonomy(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    Ok(Envelope::ok(
        &ctx,
        json!({ "categories": iot_core::taxonomy::CATEGORIES.iter().map(|c| json!({ "key": c.0, "label": c.1 })).collect::<Vec<_>>(), "types": iot_core::taxonomy::TYPES }),
    ))
}

async fn protocols(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let p: Vec<Value> = iot_core::protocols::ALL_PROTOCOLS
        .iter()
        .map(|p| json!({ "key": p.as_str(), "ports": p.ports(), "industrial": p.is_industrial(), "cleartext": p.is_cleartext() }))
        .collect();
    Ok(Envelope::ok(
        &ctx,
        json!({ "protocols": p, "operation_classes": iot_core::protocols::OP_CLASSES, "anomaly_kinds": iot_core::baseline::ANOMALY_KINDS, "finding_kinds": iot_core::vuln::FINDING_KINDS }),
    ))
}

async fn integrations(State(st): State<AppState>, ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let sync: Vec<(String, Value, chrono::DateTime<chrono::Utc>)> = sqlx::query_as("SELECT key, value, updated_at FROM sync_state ORDER BY key").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Envelope::ok(
        &ctx,
        json!({ "peers": st.peers.status(), "platform": { "url": st.platform.base(), "configured": st.platform.configured(), "health": st.platform.health() }, "sync": sync.into_iter().map(|(k, v, t)| json!({ "key": k, "value": v, "updated_at": t })).collect::<Vec<_>>() }),
    ))
}

/// Support diagnostics (no secrets).
async fn diagnostics(State(st): State<AppState>, ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let (counts,): (Value,) = sqlx::query_as(
        "SELECT jsonb_build_object('assets', (SELECT count(*) FROM assets), 'observations', (SELECT count(*) FROM observations), 'log_outbox', (SELECT count(*) FROM log_outbox), 'signal_outbox', (SELECT count(*) FROM signal_outbox),
            'outbox_pending', (SELECT count(*) FROM outbox_events WHERE dispatched_at IS NULL), 'baselines', (SELECT count(*) FROM baselines), 'config_revision', (SELECT max(revision) FROM config_revisions))",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let c = &st.cfg;
    Ok(Envelope::ok(
        &ctx,
        json!({ "version": env!("CARGO_PKG_VERSION"), "uptime_secs": st.started.elapsed().as_secs(), "counts": counts, "config": { "production": c.production, "workers": c.workers, "ingest_concurrency": c.ingest_concurrency,
            "data_region": c.data_region, "observation_retention_days": c.observation_retention_days, "history_retention_days": c.history_retention_days, "platform_url": c.platform.url, "public_url": c.public_url,
            "peers": { "branch": c.peers.branch_url.is_some(), "private_access": c.peers.private_access_url.is_some(), "firewall": c.peers.firewall_url.is_some(), "vuln_feed": c.peers.vuln_feed_url.is_some() } },
            "platform": st.platform.health(), "ingest_permits_available": st.ingest.available_permits(), "latency_p99_secs": { "ingest_batch": st.telemetry.quantile("ingest_batch", 0.99), "simulate": st.telemetry.quantile("simulate", 0.99) } }),
    ))
}

/// Product events (transactional outbox) for event consumers (section 109).
async fn events_list(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let after = q.get("after").and_then(|a| a.parse::<i64>().ok()).unwrap_or(0);
    let mut tx = ctx.tx().await?;
    let rows: Vec<(i64, Value)> = sqlx::query_as(
        "SELECT id, jsonb_build_object('seq', id, 'event_id', event_id, 'event_type', event_type, 'occurred_at', occurred_at, 'object_type', object_type, 'object_id', object_id, 'object_version', object_version, 'actor', actor, 'payload', payload)
         FROM outbox_events WHERE id > $1 AND ($2::text IS NULL OR event_type LIKE $2 || '%') ORDER BY id LIMIT $3",
    )
    .bind(after)
    .bind(q.get("type"))
    .bind(limit(&q))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let next = rows.last().map(|r| r.0).unwrap_or(after);
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.1).collect::<Vec<_>>()).meta(json!({ "next_after": next })))
}

/// Evaluate every enabled assertion over the inventory; violations raise alerts.
pub async fn evaluate_assertions(tx: &mut aether_kit::db::Tx, tenant: Uuid) -> ApiResult<Vec<Value>> {
    let asserts: Vec<(Uuid, String, String, i32)> =
        sqlx::query_as("SELECT id, name, expression, severity FROM assertions WHERE deleted_at IS NULL AND enabled").fetch_all(&mut **tx).await?;
    if asserts.is_empty() {
        return Ok(vec![]);
    }
    let assets: Vec<(Value,)> =
        sqlx::query_as("SELECT to_jsonb(a) - 'search' - 'signals' FROM assets a WHERE merged_into IS NULL AND deleted_at IS NULL LIMIT 200000").fetch_all(&mut **tx).await?;
    let mut out = vec![];
    for (id, name, expr, sev) in asserts {
        let Ok(e) = iot_core::assertions::parse(&expr) else { continue };
        let hits: Vec<&Value> = assets.iter().map(|a| &a.0).filter(|a| iot_core::assertions::eval(&e, a)).collect();
        sqlx::query("UPDATE assertions SET last_run_at = now(), violations = $2 WHERE id = $1").bind(id).bind(hits.len() as i32).execute(&mut **tx).await?;
        if !hits.is_empty() {
            pipeline::raise_alert(
                tx,
                tenant,
                "assertion",
                &format!("assertion:{id}"),
                sev,
                &format!("assertion '{name}' violated by {} devices", hits.len()),
                json!({ "assertion_id": id, "devices": hits.iter().take(50).map(|a| a["id"].clone()).collect::<Vec<_>>() }),
            )
            .await?;
        }
        out.push(json!({ "assertion_id": id, "name": name, "violations": hits.len() }));
    }
    Ok(out)
}

async fn run_assertions(ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let mut tx = ctx.tx().await?;
    let out = evaluate_assertions(&mut tx, ctx.tenant()).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, out))
}

async fn violations(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let r: Option<(String,)> = sqlx::query_as("SELECT expression FROM assertions WHERE id = $1 AND deleted_at IS NULL").bind(id).fetch_optional(&mut *tx).await?;
    let expr = r.ok_or_else(|| ApiError::not_found("assertion"))?.0;
    let e = iot_core::assertions::parse(&expr).map_err(|m| ApiError::field("expression", "invalid_expression", m))?;
    let assets: Vec<(Value,)> =
        sqlx::query_as("SELECT to_jsonb(a) - 'search' - 'signals' FROM assets a WHERE merged_into IS NULL AND deleted_at IS NULL LIMIT 200000").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let hits: Vec<Value> = assets.into_iter().map(|a| a.0).filter(|a| iot_core::assertions::eval(&e, a)).take(1000).collect();
    Ok(Envelope::ok(&ctx, hits))
}

/// Run acceptance scenarios and retain the evidence (sections 128–130).
async fn acceptance_run(ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, CREATE)?;
    let sections: Vec<u16> = match body["sections"].as_array() {
        Some(a) => a.iter().filter_map(|v| v.as_u64().map(|x| x as u16)).filter(|s| iot_core::capabilities::by_section(*s).is_some()).take(134).collect(),
        None => vec![40],
    };
    if sections.is_empty() {
        return Err(ApiError::field("sections", "invalid", "capability sections 2..135"));
    }
    let scenarios: Vec<String> = match body["scenarios"].as_array() {
        Some(a) => a.iter().filter_map(|v| v.as_str()).filter(|s| iot_core::acceptance::SCENARIOS.contains(s)).map(String::from).collect(),
        None => iot_core::acceptance::SCENARIOS.iter().map(|s| s.to_string()).collect(),
    };
    let started = chrono::Utc::now();
    let secs = sections.clone();
    let scs = scenarios.clone();
    let results = tokio::task::spawn_blocking(move || {
        let mut out = vec![];
        for s in &secs {
            for sc in &scs {
                out.push(iot_core::acceptance::run(*s, sc));
            }
        }
        out
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;
    let doc = json!(results);
    let sha = hex::encode(Sha256::digest(serde_json::to_vec(&doc).unwrap_or_default()));
    let id = Uuid::now_v7();
    let mut tx = ctx.tx().await?;
    sqlx::query("INSERT INTO acceptance_runs (id, tenant_id, started_at, finished_at, software_version, passed, failed, sections, results, sha256, created_by) VALUES ($1,$2,$3,now(),$4,$5,$6,$7,$8,$9,$10)")
        .bind(id)
        .bind(ctx.tenant())
        .bind(started)
        .bind(env!("CARGO_PKG_VERSION"))
        .bind(passed as i32)
        .bind(failed as i32)
        .bind(sections.iter().map(|s| *s as i32).collect::<Vec<_>>())
        .bind(&doc)
        .bind(&sha)
        .bind(&ctx.p.name)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, &ctx, Entry::new("acceptance_run", "acceptance_run", Some(id)).reason(format!("{passed} passed, {failed} failed"))).await?;
    events::emit_simple(&mut tx, &ctx, "acceptance_run", "completed", id, None, json!({ "id": id, "passed": passed, "failed": failed, "sha256": sha })).await?;
    tx.commit().await?;
    Ok(Envelope::created(
        &ctx,
        json!({ "id": id, "passed": passed, "failed": failed, "sha256": sha, "software_version": env!("CARGO_PKG_VERSION"), "failures": results.iter().filter(|r| !r.passed).take(20).collect::<Vec<_>>() }),
    ))
}

async fn acceptance_runs(ctx: Ctx, Query(q): Query<HashMap<String, String>>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as("SELECT to_jsonb(r) - 'results' FROM acceptance_runs r ORDER BY started_at DESC LIMIT $1").bind(limit(&q)).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

async fn acceptance_get(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let r: Option<(Value,)> = sqlx::query_as("SELECT to_jsonb(r) FROM acceptance_runs r WHERE id = $1").bind(id).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    let v = r.ok_or_else(|| ApiError::not_found("acceptance run"))?.0;
    let sha = hex::encode(Sha256::digest(serde_json::to_vec(&v["results"]).unwrap_or_default()));
    Ok(Envelope::ok(&ctx, json!({ "run": v, "integrity_verified": v["sha256"].as_str() == Some(sha.as_str()) })))
}

async fn evidence_add(ctx: Ctx, Path(id): Path<Uuid>, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let kind = body["kind"]
        .as_str()
        .filter(|k| ["asset_snapshot", "anomaly", "flows", "note", "observation", "decision", "file_digest"].contains(k))
        .ok_or_else(|| ApiError::field("kind", "invalid", "asset_snapshot, anomaly, flows, note, observation, decision, file_digest"))?;
    let data = body["data"].clone();
    if serde_json::to_vec(&data).map(|b| b.len()).unwrap_or(0) > 256 * 1024 {
        return Err(ApiError::payload_too_large("evidence is limited to 256 KiB (store large files elsewhere and record their digest)"));
    }
    let mut tx = ctx.tx().await?;
    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM investigations WHERE id = $1 AND deleted_at IS NULL").bind(id).fetch_optional(&mut *tx).await?;
    exists.ok_or_else(|| ApiError::not_found("investigation"))?;
    // Snapshot the referenced object as it is now.
    let data = match (kind, body["ref"].as_str().and_then(|r| Uuid::parse_str(r).ok())) {
        ("asset_snapshot", Some(a)) => super::assets::load(&mut tx, a).await?,
        ("flows", Some(a)) => {
            let r: Vec<(Value,)> = sqlx::query_as("SELECT to_jsonb(f) FROM flow_rollups f WHERE asset_id = $1 AND bucket > now() - interval '24 hours' LIMIT 1000")
                .bind(a)
                .fetch_all(&mut *tx)
                .await?;
            json!(r.into_iter().map(|x| x.0).collect::<Vec<_>>())
        }
        ("anomaly", Some(a)) => sqlx::query_as::<_, (Value,)>("SELECT to_jsonb(x) FROM anomalies x WHERE id = $1")
            .bind(a)
            .fetch_optional(&mut *tx)
            .await?
            .map(|x| x.0)
            .ok_or_else(|| ApiError::not_found("anomaly"))?,
        _ => data,
    };
    let sha = hex::encode(Sha256::digest(serde_json::to_vec(&data).unwrap_or_default()));
    let eid = Uuid::now_v7();
    sqlx::query("INSERT INTO evidence (id, tenant_id, investigation_id, kind, ref, sha256, data, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(eid)
        .bind(ctx.tenant())
        .bind(id)
        .bind(kind)
        .bind(body["ref"].as_str())
        .bind(&sha)
        .bind(&data)
        .bind(&ctx.p.name)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, &ctx, Entry::new("add_evidence", "investigation", Some(id)).reason(format!("{kind} {sha}"))).await?;
    tx.commit().await?;
    Ok(Envelope::created(&ctx, json!({ "id": eid, "investigation_id": id, "kind": kind, "sha256": sha })))
}

async fn evidence_list(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let rows: Vec<(Value,)> = sqlx::query_as("SELECT to_jsonb(e) FROM evidence e WHERE investigation_id = $1 ORDER BY created_at").bind(id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let mut v = r.0;
            let ok = hex::encode(Sha256::digest(serde_json::to_vec(&v["data"]).unwrap_or_default())) == v["sha256"].as_str().unwrap_or("");
            v["integrity_verified"] = json!(ok);
            v
        })
        .collect();
    Ok(Envelope::ok(&ctx, items))
}

async fn investigation_timeline(ctx: Ctx, Path(id): Path<Uuid>) -> ApiResult<Envelope> {
    pre(&ctx, READ)?;
    let mut tx = ctx.tx().await?;
    let r: Option<(Vec<Uuid>, Vec<Uuid>)> =
        sqlx::query_as("SELECT asset_ids, anomaly_ids FROM investigations WHERE id = $1 AND deleted_at IS NULL").bind(id).fetch_optional(&mut *tx).await?;
    let (assets, anoms) = r.ok_or_else(|| ApiError::not_found("investigation"))?;
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT x FROM (
            SELECT jsonb_build_object('at', at, 'type', 'asset_change', 'asset_id', asset_id, 'kind', kind, 'detail', detail) x, at FROM asset_changes WHERE asset_id = ANY($1)
            UNION ALL SELECT jsonb_build_object('at', first_seen, 'type', 'anomaly', 'asset_id', asset_id, 'kind', kind, 'title', title, 'severity', severity), first_seen FROM anomalies WHERE asset_id = ANY($1) OR id = ANY($2)
            UNION ALL SELECT jsonb_build_object('at', started_at, 'type', 'remote_session', 'session_id', s.id, 'user', s.user_email, 'end_reason', s.end_reason), started_at FROM remote_sessions s JOIN access_requests r ON r.id = s.request_id JOIN remote_targets t ON t.id = r.target_id WHERE t.asset_id = ANY($1)
         ) y ORDER BY at DESC LIMIT 1000",
    )
    .bind(&assets)
    .bind(&anoms)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, rows.into_iter().map(|r| r.0).collect::<Vec<_>>()))
}

/// Fingerprint propagation: learn TLS/DHCP rules from confident devices.
pub async fn learn_rules(st: &AppState, tenant: Uuid) -> ApiResult<usize> {
    let mut tx = aether_kit::db::tenant_tx(&st.pool, tenant).await?;
    let rows: Vec<(Value, Option<String>, String, f64)> =
        sqlx::query_as("SELECT signals, mac, device_type, confidence FROM assets WHERE merged_into IS NULL AND tier = 'high' AND device_type <> 'unknown' LIMIT 50000")
            .fetch_all(&mut *tx)
            .await?;
    let devices: Vec<(std::collections::BTreeSet<iot_core::classify::Fact>, String, f64)> = rows
        .into_iter()
        .map(|(sig, mac, ty, c)| {
            let signals: Vec<iot_core::model::Signal> = serde_json::from_value(sig).unwrap_or_default();
            (iot_core::classify::facts(mac.as_deref(), &signals, &iot_core::fingerprint::OuiTable::default()), ty, c)
        })
        .collect();
    let rules = iot_core::classify::learn_rules(&devices, 3);
    let mut n = 0;
    for r in rules {
        let exists: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM classification_rules WHERE origin = 'learned' AND source = $1 AND field = $2 AND pattern = $3 AND deleted_at IS NULL")
                .bind(&r.source)
                .bind(&r.field)
                .bind(&r.pattern)
                .fetch_optional(&mut *tx)
                .await?;
        if exists.is_some() {
            continue;
        }
        sqlx::query(
            "INSERT INTO classification_rules (id, tenant_id, name, source, field, match, pattern, device_type, weight, origin) VALUES ($1,$2,$3,$4,$5,'exact',$6,$7,$8,'learned')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(format!("learned {} {}", r.source, r.device_type.clone().unwrap_or_default()))
        .bind(&r.source)
        .bind(&r.field)
        .bind(&r.pattern)
        .bind(&r.device_type)
        .bind(r.weight)
        .execute(&mut *tx)
        .await?;
        n += 1;
    }
    tx.commit().await?;
    if n > 0 {
        st.invalidate(tenant);
    }
    Ok(n)
}

async fn learn(State(st): State<AppState>, ctx: Ctx) -> ApiResult<Envelope> {
    pre(&ctx, UPDATE)?;
    let n = learn_rules(&st, ctx.tenant()).await?;
    audit::record_standalone(&ctx, Entry::new("learn_rules", "classification_rule", None::<Uuid>).reason(format!("{n} rules learned"))).await;
    Ok(Envelope::ok(&ctx, json!({ "learned": n })))
}

/// Erase a person's data held by this product (vendor principal, access
/// requests and session records keep their audit facts, the e-mail is
/// replaced by a pseudonym).
async fn erase(ctx: Ctx, Json(body): Json<Value>) -> ApiResult<Envelope> {
    pre(&ctx, DELETE)?;
    let email = body["email"].as_str().map(|e| e.trim().to_ascii_lowercase()).filter(|e| e.contains('@')).ok_or_else(|| ApiError::field("email", "required", "e-mail address"))?;
    let pseudo = format!("erased-{}", &hex::encode(Sha256::digest(email.as_bytes()))[..12]);
    let mut tx = ctx.tx().await?;
    let a = sqlx::query("UPDATE access_requests SET requester_email = $2 WHERE lower(requester_email) = $1").bind(&email).bind(&pseudo).execute(&mut *tx).await?.rows_affected();
    let s = sqlx::query("UPDATE remote_sessions SET user_email = $2, client_ip = NULL WHERE lower(user_email) = $1")
        .bind(&email)
        .bind(&pseudo)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let v = sqlx::query("UPDATE vendor_principals SET email = $2 || '@erased.invalid', name = $2, phone = NULL, notes = NULL, enabled = false, deleted_at = coalesce(deleted_at, now()) WHERE lower(email) = $1").bind(&email).bind(&pseudo).execute(&mut *tx).await?.rows_affected();
    audit::record(&mut tx, &ctx, Entry::new("privacy_erase", "person", None::<Uuid>).reason(format!("{pseudo}: {a} requests, {s} sessions, {v} vendor principals"))).await?;
    tx.commit().await?;
    Ok(Envelope::ok(&ctx, json!({ "pseudonym": pseudo, "access_requests": a, "sessions": s, "vendor_principals": v })))
}
