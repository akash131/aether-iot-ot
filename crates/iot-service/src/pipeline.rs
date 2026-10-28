//! Ingestion and evaluation pipeline (ZTE-IOT sections 4, 7, 14–20, 53,
//! 58–69, 71–72, 92–97; Volume 2 "Asset Discovery", "Device
//! Classification", "Risk Profiling", "Passive Telemetry", "Anomaly
//! Signals", "Asset Lifecycle").
//!
//! For every observation an enrolled sensor sends:
//!
//! 1. validate and minimise it; force the sensor's site (a sensor cannot
//!    report for another site);
//! 2. resolve the asset identity from MAC, serial, DHCP client id, host
//!    name and (site-scoped, corroborated) IP; record identity keys and
//!    change events (IP change, site move, MAC change);
//! 3. merge evidence, classify with the tenant classifier (built-in +
//!    custom + learned rules), apply the administrator override, record
//!    classification history and firmware changes;
//! 4. assess exposure and vulnerabilities against the configured feed;
//! 5. update the communication baseline and raise anomalies;
//! 6. roll flows up into the hourly time series and the dependency graph;
//! 7. recompute risk (tenant tuning) and the device's groups and zone
//!    (dynamic segmentation, never privileged when uncertain);
//! 8. queue typed log records and risk signals for the platform and emit
//!    outbox events.
//!
//! Batches are idempotent by `batch_id`; each observation is processed in
//! its own transaction so a bad record never blocks the batch.

use crate::state::AppState;
use aether_kit::{events, ApiError, ApiResult, Ctx};
use chrono::{Duration, DurationRound, Utc};
use iot_core::baseline::{self, Baseline, DetectContext, LearningPolicy};
use iot_core::classify::{self, Classification, Fact, Override};
use iot_core::identity::{self, AssetKeys, ChangeEvent, ObsKeys, Strength};
use iot_core::model::{Flow, Observation, Signal};
use iot_core::protocols::{OpClass, ProtoEvent};
use iot_core::risk::{self, Tuning};
use iot_core::segmentation::{self, DeviceFacts, Group, GroupMatch, Mode, Zone};
use iot_core::taxonomy::{self, Lifecycle};
use iot_core::vuln::{self, ExposureInput, Finding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

type Tx = aether_kit::db::Tx;

/// Typed attributes of this product's log types (platform log schemas).
pub fn log_schemas() -> Vec<(&'static str, Value)> {
    let f = |name: &str, ty: &str, req: bool| json!({ "name": name, "type": ty, "required": req });
    vec![
        (
            "iot_discovery",
            json!([
                f("asset_id", "string", true),
                f("mac", "string", false),
                f("ip", "ip", false),
                f("device_type", "string", true),
                f("category", "string", true),
                f("vendor", "string", false),
                f("model", "string", false),
                f("confidence", "number", true),
                f("site_id", "string", false),
                f("sensor_id", "string", false),
                f("event", "string", true)
            ]),
        ),
        (
            "iot_anomaly",
            json!([f("asset_id", "string", true), f("anomaly_id", "string", true), f("kind", "string", true), f("severity", "number", true), f("device_type", "string", false)]),
        ),
        (
            "iot_risk",
            json!([f("asset_id", "string", true), f("score", "integer", true), f("level", "string", true), f("previous_level", "string", false), f("priority", "integer", false)]),
        ),
        (
            "iot_flow",
            json!([
                f("asset_id", "string", true),
                f("peer_ip", "ip", true),
                f("port", "integer", true),
                f("transport", "string", true),
                f("protocol", "string", false),
                f("max_op", "string", false),
                f("outbound", "boolean", true),
                f("bytes", "integer", false)
            ]),
        ),
        (
            "iot_finding",
            json!([f("asset_id", "string", true), f("finding_id", "string", true), f("kind", "string", true), f("key", "string", true), f("severity", "number", true)]),
        ),
        (
            "iot_decision",
            json!([
                f("node_id", "string", true),
                f("enforced", "string", true),
                f("policy_action", "string", true),
                f("mode", "string", false),
                f("source_asset", "string", false),
                f("destination_asset", "string", false),
                f("protocol", "string", false),
                f("operation_class", "string", false),
                f("count", "integer", false)
            ]),
        ),
        (
            "iot_remote_access",
            json!([f("request_id", "string", true), f("event", "string", true), f("target_id", "string", false), f("vendor", "string", false), f("session_id", "string", false)]),
        ),
    ]
}

/// Queue a platform log record (shipped by the log worker).
pub async fn log(tx: &mut Tx, tenant: Uuid, log_type: &str, action: &str, device: Option<Uuid>, destination: Option<String>, attrs: Value) -> ApiResult<()> {
    let rec = json!({ "event_id": Uuid::now_v7(), "occurred_at": Utc::now(), "log_type": log_type, "action": action, "device_id": device, "destination": destination, "policy_type": null, "attributes": attrs });
    sqlx::query("INSERT INTO log_outbox (tenant_id, record) VALUES ($1, $2)").bind(tenant).bind(rec).execute(&mut **tx).await?;
    Ok(())
}

/// Queue a risk signal for the platform.
pub async fn signal(tx: &mut Tx, tenant: Uuid, s: Value) -> ApiResult<()> {
    sqlx::query("INSERT INTO signal_outbox (tenant_id, signal) VALUES ($1, $2)").bind(tenant).bind(s).execute(&mut **tx).await?;
    Ok(())
}

/// Record an asset change event.
pub async fn change(tx: &mut Tx, tenant: Uuid, asset: Uuid, kind: &str, detail: Value, actor: &str) -> ApiResult<()> {
    sqlx::query("INSERT INTO asset_changes (id, tenant_id, asset_id, kind, detail, actor) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(asset)
        .bind(kind)
        .bind(detail)
        .bind(actor)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Read a tenant settings document (defaults when absent).
pub async fn settings(tx: &mut Tx, name: &str) -> ApiResult<Value> {
    let r: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE name = $1 AND deleted_at IS NULL").bind(name).fetch_optional(&mut **tx).await?;
    Ok(r.map(|x| x.0).unwrap_or_else(|| json!({})))
}

/// Groups and zones of the tenant.
pub async fn groups_zones(tx: &mut Tx) -> ApiResult<(Vec<Group>, Vec<Zone>)> {
    let zr: Vec<(Uuid, String, i32, String, bool)> =
        sqlx::query_as("SELECT id, key, security_level, mode, safety_critical FROM zones WHERE deleted_at IS NULL").fetch_all(&mut **tx).await?;
    let zones = zr
        .into_iter()
        .map(|(id, key, sl, mode, safety)| Zone {
            id: id.to_string(),
            key,
            security_level: sl.clamp(1, 4) as u8,
            mode: Mode::parse(&mode).unwrap_or(Mode::Observe),
            safety_critical: safety,
        })
        .collect();
    let gr: Vec<(Uuid, String, i32, Value, Option<Uuid>, bool, f64)> =
        sqlx::query_as("SELECT id, key, priority, match, zone_id, privileged, min_confidence FROM device_groups WHERE deleted_at IS NULL").fetch_all(&mut **tx).await?;
    let groups = gr
        .into_iter()
        .map(|(id, key, priority, m, zone, privileged, minc)| Group {
            id: id.to_string(),
            key,
            priority,
            matcher: serde_json::from_value::<GroupMatch>(m).unwrap_or_default(),
            zone: zone.map(|z| z.to_string()),
            privileged,
            min_confidence: minc,
        })
        .collect();
    Ok((groups, zones))
}

/// Per-batch tenant context.
pub struct TenantCtx {
    pub classifier: std::sync::Arc<iot_core::classify::Classifier>,
    pub groups: Vec<Group>,
    pub zones: Vec<Zone>,
    pub threats: BTreeSet<String>,
    pub tuning: Tuning,
    pub learning: LearningPolicy,
}

pub async fn tenant_ctx(state: &AppState, tenant: Uuid) -> ApiResult<TenantCtx> {
    let classifier = state.classifier(tenant).await.map_err(|e| ApiError::internal(e.to_string()))?;
    let mut tx = aether_kit::db::tenant_tx(&state.pool, tenant).await?;
    let (groups, zones) = groups_zones(&mut tx).await?;
    let threats: Vec<(String,)> =
        sqlx::query_as("SELECT lower(indicator) FROM threat_indicators WHERE deleted_at IS NULL AND (expires_at IS NULL OR expires_at > now()) LIMIT 100000")
            .fetch_all(&mut *tx)
            .await?;
    let tuning: Tuning = serde_json::from_value(settings(&mut tx, "risk_tuning").await?).unwrap_or_default();
    let learning: LearningPolicy = serde_json::from_value(settings(&mut tx, "learning").await?).unwrap_or_default();
    tx.commit().await?;
    Ok(TenantCtx { classifier, groups, zones, threats: threats.into_iter().map(|t| t.0).collect(), tuning, learning })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Batch {
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub sensor_id: Option<Uuid>,
    #[serde(default)]
    pub observations: Vec<Observation>,
    /// Collector statistics (capture, decode and parser errors).
    #[serde(default)]
    pub stats: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Outcome {
    pub accepted: usize,
    pub rejected: Vec<Value>,
    pub created: usize,
    pub updated: usize,
    pub anomalies: usize,
    pub duplicate: bool,
    pub assets: Vec<Uuid>,
}

/// Process a batch (idempotent by `batch_id`).
pub async fn ingest(state: &AppState, ctx: &Ctx, site: Option<Uuid>, batch: Batch) -> ApiResult<Outcome> {
    if batch.observations.len() > iot_core::model::MAX_OBSERVATIONS_PER_BATCH {
        return Err(ApiError::payload_too_large(format!("at most {} observations per batch", iot_core::model::MAX_OBSERVATIONS_PER_BATCH)));
    }
    let _permit = state.ingest.clone().try_acquire_owned().map_err(|_| ApiError::too_many_requests(2))?;
    let started = std::time::Instant::now();
    let tenant = ctx.tenant();
    if let Some(b) = &batch.batch_id {
        if b.is_empty() || b.len() > 128 {
            return Err(ApiError::field("batch_id", "invalid", "1..128 characters"));
        }
        let mut tx = ctx.tx().await?;
        let prev: Option<(i32, Value)> = sqlx::query_as("SELECT accepted, rejected FROM ingest_batches WHERE batch_id = $1").bind(b).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        if let Some((a, r)) = prev {
            return Ok(Outcome { accepted: a as usize, rejected: r.as_array().cloned().unwrap_or_default(), duplicate: true, ..Default::default() });
        }
    }
    let tc = tenant_ctx(state, tenant).await?;
    let now = Utc::now();
    let mut out = Outcome::default();
    for (i, mut o) in batch.observations.into_iter().enumerate() {
        if let Err(code) = o.sanitize(now) {
            out.rejected.push(json!({ "index": i, "code": code }));
            continue;
        }
        if site.is_some() {
            o.site = site.map(|s| s.to_string());
        }
        let mut tx = ctx.tx().await?;
        match process(state, ctx, &mut tx, &tc, &o, batch.sensor_id, batch.batch_id.as_deref()).await {
            Ok(r) => {
                tx.commit().await?;
                out.accepted += 1;
                if r.created {
                    out.created += 1;
                } else {
                    out.updated += 1;
                }
                out.anomalies += r.anomalies;
                if !out.assets.contains(&r.asset) && out.assets.len() < 1000 {
                    out.assets.push(r.asset);
                }
            }
            Err(e) => {
                let _ = tx.rollback().await;
                state.metrics.count("ingest_observation", "error");
                tracing::warn!(error = %e.detail, "observation rejected");
                out.rejected.push(json!({ "index": i, "code": e.code, "detail": e.detail }));
            }
        }
    }
    if let Some(stats) = &batch.stats {
        record_protocol_stats(state, tenant, site, stats).await?;
    }
    if let Some(b) = &batch.batch_id {
        let mut tx = ctx.tx().await?;
        sqlx::query("INSERT INTO ingest_batches (tenant_id, batch_id, sensor_id, accepted, rejected) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(tenant)
            .bind(b)
            .bind(batch.sensor_id)
            .bind(out.accepted as i32)
            .bind(json!(out.rejected))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    state.metrics.count("ingest_batch", "ok");
    state.telemetry.observe("ingest_batch", started.elapsed());
    Ok(out)
}

/// Collector statistics → protocol telemetry rollups.
async fn record_protocol_stats(state: &AppState, tenant: Uuid, site: Option<Uuid>, stats: &Value) -> ApiResult<()> {
    let bucket = Utc::now().duration_trunc(Duration::hours(1)).unwrap_or_else(|_| Utc::now());
    let mut tx = aether_kit::db::tenant_tx(&state.pool, tenant).await?;
    let put = |p: String, op: String, class: String, ev: i64, err: i64| (p, op, class, ev, err);
    let mut rows = vec![];
    if let Some(m) = stats["protocol_events"].as_object() {
        for (p, n) in m.iter().take(64) {
            rows.push(put(p.clone(), "*".into(), "*".into(), n.as_i64().unwrap_or(0), 0));
        }
    }
    if let Some(m) = stats["parse_errors"].as_object() {
        for (k, n) in m.iter().take(64) {
            let (p, code) = k.split_once(':').unwrap_or((k.as_str(), "error"));
            rows.push(put(p.to_string(), format!("error:{code}"), "*".into(), 0, n.as_i64().unwrap_or(0)));
        }
    }
    for (p, op, class, ev, err) in rows {
        sqlx::query(
            "INSERT INTO protocol_stats (tenant_id, site_id, bucket, protocol, operation, op_class, events, errors) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (tenant_id, coalesce(site_id, '00000000-0000-0000-0000-000000000000'::uuid), bucket, protocol, operation, op_class)
             DO UPDATE SET events = protocol_stats.events + EXCLUDED.events, errors = protocol_stats.errors + EXCLUDED.errors",
        )
        .bind(tenant)
        .bind(site)
        .bind(bucket)
        .bind(&p)
        .bind(&op)
        .bind(&class)
        .bind(ev)
        .bind(err)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub struct Processed {
    pub asset: Uuid,
    pub created: bool,
    pub anomalies: usize,
}

fn keys_of(o: &Observation) -> ObsKeys {
    let mut k = ObsKeys { site: o.site.clone(), mac: o.mac.clone(), ip: o.ip.clone(), ..Default::default() };
    for s in &o.signals {
        match s {
            Signal::Dhcp { hostname, client_id, .. } => {
                if hostname.is_some() {
                    k.hostname = hostname.clone();
                }
                if client_id.is_some() {
                    k.client_id = client_id.clone();
                }
            }
            Signal::Protocol { event, .. } => {
                if let (Some(v), Some(s)) = (&event.identity.vendor, &event.identity.serial) {
                    k.serial = Some(format!("{v}/{s}"));
                }
            }
            Signal::Tls { fingerprint, .. } => k.tls_fingerprint = Some(fingerprint.clone()),
            Signal::Asserted { hostname: Some(h), .. } => k.hostname = Some(h.clone()),
            _ => {}
        }
    }
    k
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(String::from)
}

async fn candidates(tx: &mut Tx, k: &ObsKeys) -> ApiResult<Vec<AssetKeys>> {
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT jsonb_build_object('id', id, 'site', site_id::text, 'mac', mac, 'ip', ip, 'hostname', hostname, 'serial', serial, 'client_id', client_id, 'tls_fingerprint', tls_fingerprint,
                'decommissioned', lifecycle = 'decommissioned', 'merged', merged_into IS NOT NULL)
         FROM assets WHERE deleted_at IS NULL AND merged_into IS NULL AND (
             ($1::text IS NOT NULL AND mac = $1) OR ($2::text IS NOT NULL AND serial = $2)
             OR ($3::text IS NOT NULL AND lower(hostname) = lower($3)) OR ($4::text IS NOT NULL AND client_id = $4)
             OR ($5::text IS NOT NULL AND ip = $5 AND site_id::text IS NOT DISTINCT FROM $6))
         ORDER BY last_seen DESC LIMIT 25",
    )
    .bind(&k.mac)
    .bind(&k.serial)
    .bind(&k.hostname)
    .bind(&k.client_id)
    .bind(&k.ip)
    .bind(&k.site)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().filter_map(|r| serde_json::from_value(r.0).ok()).collect())
}

/// Process one observation inside `tx`.
pub async fn process(state: &AppState, ctx: &Ctx, tx: &mut Tx, tc: &TenantCtx, o: &Observation, sensor: Option<Uuid>, batch: Option<&str>) -> ApiResult<Processed> {
    let tenant = ctx.tenant();
    let now = Utc::now();
    let k = keys_of(o);
    let cands = candidates(tx, &k).await?;
    let r = identity::resolve(&cands, &k);
    let site_id = o.site.as_deref().and_then(|x| Uuid::parse_str(x).ok());
    let (id, created) = match r.asset {
        Some(id) => (id, false),
        None => {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO assets (id, tenant_id, site_id, mac, ip, hostname, serial, client_id, tls_fingerprint, randomized_mac, vlan, identity_strength, first_seen, last_seen, last_sensor_id, lifecycle)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,'discovered')",
            )
            .bind(id)
            .bind(tenant)
            .bind(site_id)
            .bind(&k.mac)
            .bind(&k.ip)
            .bind(&k.hostname)
            .bind(&k.serial)
            .bind(&k.client_id)
            .bind(&k.tls_fingerprint)
            .bind(k.randomized_mac())
            .bind(o.vlan.map(|v| v as i32))
            .bind(if k.mac.is_some() && !k.randomized_mac() || k.serial.is_some() { "strong" } else if k.hostname.is_some() || k.client_id.is_some() { "medium" } else { "weak" })
            .bind(o.observed_at.min(now))
            .bind(sensor)
            .execute(&mut **tx)
            .await?;
            (id, true)
        }
    };
    // Identity keys and change events.
    for (kt, v) in [("mac", &k.mac), ("serial", &k.serial), ("hostname", &k.hostname), ("client_id", &k.client_id), ("ip", &k.ip), ("tls", &k.tls_fingerprint)] {
        if let Some(v) = v {
            sqlx::query(
                "INSERT INTO asset_identities (tenant_id, asset_id, key_type, value, site_id) VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (tenant_id, asset_id, key_type, value) DO UPDATE SET last_seen = now()",
            )
            .bind(tenant)
            .bind(id)
            .bind(kt)
            .bind(v)
            .bind(site_id)
            .execute(&mut **tx)
            .await?;
        }
    }
    for c in &r.changes {
        let kind = match c {
            ChangeEvent::IpChanged { .. } => "ip_changed",
            ChangeEvent::SiteMoved { .. } => "site_moved",
            ChangeEvent::MacChanged { .. } => "mac_changed",
            ChangeEvent::HostnameChanged { .. } => "hostname_changed",
        };
        change(tx, tenant, id, kind, serde_json::to_value(c).unwrap_or_default(), "system").await?;
    }
    if !r.merge_candidates.is_empty() || r.split_suspected {
        raise_alert(
            tx,
            tenant,
            "identity_review",
            &format!("identity:{id}"),
            4,
            "asset identity needs review (merge or split candidate)",
            json!({ "asset_id": id, "merge_candidates": r.merge_candidates, "split_suspected": r.split_suspected }),
        )
        .await?;
    }
    if created {
        change(tx, tenant, id, "discovered", json!({ "mac": k.mac, "ip": k.ip, "site_id": site_id, "sensor_id": sensor, "passive": o.passive }), "system").await?;
    }
    // Current row.
    let (row,): (Value,) = sqlx::query_as("SELECT to_jsonb(a) - 'search' FROM assets a WHERE id = $1 FOR UPDATE").bind(id).fetch_one(&mut **tx).await?;
    let mut signals: Vec<Signal> = serde_json::from_value(row["signals"].clone()).unwrap_or_default();
    for sgl in &o.signals {
        let mut sg = sgl.clone();
        if let Signal::Protocol { event, .. } = &mut sg {
            event.values.clear();
        }
        if !signals.contains(&sg) {
            if signals.len() >= 128 {
                signals.remove(0);
            }
            signals.push(sg);
        }
    }
    let decommissioned = row["lifecycle"] == "decommissioned";
    if decommissioned {
        change(tx, tenant, id, "reactivated", json!({ "reason": "observed after decommissioning" }), "system").await?;
    }
    // Raw observation (short retention; minimised).
    sqlx::query("INSERT INTO observations (id, tenant_id, asset_id, sensor_id, batch_id, observed_at, passive, data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(id)
        .bind(sensor)
        .bind(batch)
        .bind(o.observed_at)
        .bind(o.passive)
        .bind(serde_json::to_value(o).unwrap_or_default())
        .execute(&mut **tx)
        .await?;
    let ip_new = k.ip.clone().or_else(|| s(&row, "ip"));
    sqlx::query(
        "UPDATE assets SET signals = $2, ip = coalesce($3, ip), hostname = coalesce($4, hostname), serial = coalesce($5, serial), client_id = coalesce($6, client_id),
             tls_fingerprint = coalesce($7, tls_fingerprint), site_id = coalesce($8, site_id), mac = coalesce($9, mac), vlan = coalesce($10, vlan), last_seen = greatest(last_seen, $11),
             last_sensor_id = coalesce($12, last_sensor_id), lifecycle = CASE WHEN lifecycle IN ('discovered','inactive','decommissioned') THEN 'active' ELSE lifecycle END,
             decommissioned_at = NULL, updated_at = now(), version = version + 1
         WHERE id = $1",
    )
    .bind(id)
    .bind(serde_json::to_value(&signals).unwrap_or_default())
    .bind(&ip_new)
    .bind(&k.hostname)
    .bind(&k.serial)
    .bind(&k.client_id)
    .bind(&k.tls_fingerprint)
    .bind(site_id)
    .bind(&k.mac)
    .bind(o.vlan.map(|v| v as i32))
    .bind(o.observed_at.min(now))
    .bind(sensor)
    .execute(&mut **tx)
    .await?;
    // Flows: rollups and graph.
    let bucket = o.observed_at.duration_trunc(Duration::hours(1)).unwrap_or(o.observed_at);
    for f in o.flows.iter().take(iot_core::model::MAX_FLOWS) {
        let peer_asset: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM assets WHERE ip = $1 AND merged_into IS NULL AND deleted_at IS NULL ORDER BY last_seen DESC LIMIT 1")
            .bind(&f.peer_ip)
            .fetch_optional(&mut **tx)
            .await?;
        let peer_asset = peer_asset.map(|p| p.0).filter(|p| *p != id);
        sqlx::query(
            "INSERT INTO flow_rollups (tenant_id, asset_id, bucket, peer_ip, transport, port, outbound, peer_asset_id, protocol, max_op, operations, packets, bytes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (tenant_id, asset_id, bucket, peer_ip, transport, port, outbound) DO UPDATE SET packets = flow_rollups.packets + EXCLUDED.packets, bytes = flow_rollups.bytes + EXCLUDED.bytes,
                peer_asset_id = coalesce(EXCLUDED.peer_asset_id, flow_rollups.peer_asset_id), protocol = coalesce(EXCLUDED.protocol, flow_rollups.protocol),
                max_op = CASE WHEN EXCLUDED.max_op IS NULL THEN flow_rollups.max_op WHEN flow_rollups.max_op IS NULL THEN EXCLUDED.max_op
                              WHEN array_position(ARRAY['session','read','diagnostic','write','control','program','firmware'], EXCLUDED.max_op) > array_position(ARRAY['session','read','diagnostic','write','control','program','firmware'], flow_rollups.max_op)
                              THEN EXCLUDED.max_op ELSE flow_rollups.max_op END,
                operations = (SELECT array_agg(DISTINCT x) FROM unnest(flow_rollups.operations || EXCLUDED.operations) x)",
        )
        .bind(tenant)
        .bind(id)
        .bind(bucket)
        .bind(&f.peer_ip)
        .bind(&f.transport)
        .bind(f.port as i32)
        .bind(f.outbound)
        .bind(peer_asset)
        .bind(f.protocol.map(|p| p.as_str()))
        .bind(f.max_op.map(|m| m.as_str()))
        .bind(&f.operations)
        .bind(f.packets as i64)
        .bind(f.bytes as i64)
        .execute(&mut **tx)
        .await?;
        let me = id.to_string();
        let peer = peer_asset.map(|p| p.to_string()).unwrap_or_else(|| f.peer_ip.clone());
        let (from, to, fa, ta) = if f.outbound { (me.clone(), peer.clone(), Some(id), peer_asset) } else { (peer.clone(), me.clone(), peer_asset, Some(id)) };
        sqlx::query(
            "INSERT INTO graph_edges (tenant_id, from_node, to_node, from_asset, to_asset, protocols, ports, max_op, bytes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (tenant_id, from_node, to_node) DO UPDATE SET last_seen = now(), bytes = graph_edges.bytes + EXCLUDED.bytes,
                protocols = (SELECT array_agg(DISTINCT x) FROM unnest(graph_edges.protocols || EXCLUDED.protocols) x),
                ports = (SELECT array_agg(DISTINCT x) FROM (SELECT unnest(graph_edges.ports || EXCLUDED.ports) x LIMIT 64) y),
                max_op = coalesce(EXCLUDED.max_op, graph_edges.max_op)",
        )
        .bind(tenant)
        .bind(&from)
        .bind(&to)
        .bind(fa)
        .bind(ta)
        .bind(f.protocol.map(|p| vec![p.as_str().to_string()]).unwrap_or_default())
        .bind(vec![f.port as i32])
        .bind(f.max_op.map(|m| m.as_str()))
        .bind(f.bytes as i64)
        .execute(&mut **tx)
        .await?;
    }
    for f in o.flows.iter().take(16) {
        log(
            tx,
            tenant,
            "iot_flow",
            "observe",
            Some(id),
            Some(format!("{}:{}", f.peer_ip, f.port)),
            json!({ "asset_id": id.to_string(), "peer_ip": f.peer_ip, "port": f.port, "transport": f.transport, "protocol": f.protocol.map(|p| p.as_str()), "max_op": f.max_op.map(|m| m.as_str()), "outbound": f.outbound, "bytes": f.bytes }),
        )
        .await?;
    }
    let events: Vec<(ProtoEvent, bool)> = o.signals.iter().filter_map(|x| if let Signal::Protocol { event, server } = x { Some((event.clone(), *server)) } else { None }).collect();
    let anomalies = evaluate(state, ctx, tx, tc, id, &o.flows, &events, created).await?;
    Ok(Processed { asset: id, created, anomalies })
}

/// Raise (or bump) a system alert.
pub async fn raise_alert(tx: &mut Tx, tenant: Uuid, kind: &str, dedup: &str, severity: i32, title: &str, detail: Value) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO alerts (id, tenant_id, kind, dedup_key, severity, title, detail) VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (tenant_id, dedup_key) WHERE status = 'open' DO UPDATE SET count = alerts.count + 1, last_seen = now(), detail = EXCLUDED.detail, severity = greatest(alerts.severity, EXCLUDED.severity)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(kind)
    .bind(dedup)
    .bind(severity)
    .bind(title)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Recent flows of an asset (last 24 h of rollups) for behaviour and risk.
async fn recent_flows(tx: &mut Tx, asset: Uuid) -> ApiResult<Vec<Flow>> {
    let rows: Vec<(String, String, i32, bool, Option<String>, Option<String>, i64, i64, Vec<String>)> = sqlx::query_as(
        "SELECT peer_ip, transport, port, outbound, protocol, max_op, sum(packets)::bigint, sum(bytes)::bigint, (array_agg(operations))[1]
         FROM flow_rollups WHERE asset_id = $1 AND bucket > now() - interval '24 hours'
         GROUP BY peer_ip, transport, port, outbound, protocol, max_op LIMIT 512",
    )
    .bind(asset)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(peer_ip, transport, port, outbound, protocol, max_op, packets, bytes, operations)| Flow {
            peer_ip,
            peer_mac: None,
            transport,
            port: port as u16,
            outbound,
            packets: packets as u64,
            bytes: bytes as u64,
            protocol: protocol.as_deref().and_then(iot_core::protocols::Protocol::parse),
            max_op: max_op.as_deref().and_then(segmentation::op_class),
            operations,
        })
        .collect())
}

/// Re-evaluate an asset: classification, findings, baseline anomalies,
/// risk and segment assignment. Returns the number of new anomalies.
#[allow(clippy::too_many_arguments)]
pub async fn evaluate(state: &AppState, ctx: &Ctx, tx: &mut Tx, tc: &TenantCtx, id: Uuid, new_flows: &[Flow], events: &[(ProtoEvent, bool)], created: bool) -> ApiResult<usize> {
    let tenant = ctx.tenant();
    let now = Utc::now();
    let (row,): (Value,) = sqlx::query_as("SELECT to_jsonb(a) - 'search' FROM assets a WHERE id = $1").bind(id).fetch_one(&mut **tx).await?;
    if row["lifecycle"] == "merged" {
        return Ok(0);
    }
    let signals: Vec<Signal> = serde_json::from_value(row["signals"].clone()).unwrap_or_default();
    let mac = s(&row, "mac");
    let flows = recent_flows(tx, id).await?;
    let mut facts: BTreeSet<Fact> = classify::facts(mac.as_deref(), &signals, &iot_core::fingerprint::OuiTable::default());
    facts.extend(classify::behaviour_facts(&flows));
    let mut c: Classification = tc.classifier.classify(&facts);
    let ov: Override = serde_json::from_value(row["classification_override"].clone()).unwrap_or_default();
    c = ov.apply(c);
    let prev_type = s(&row, "device_type").unwrap_or_else(|| "unknown".into());
    let prev_tier = s(&row, "tier").unwrap_or_default();
    let prev_fw = s(&row, "firmware");
    if c.device_type != prev_type || c.tier != prev_tier || created {
        sqlx::query("INSERT INTO classification_history (id, tenant_id, asset_id, device_type, confidence, source, ruleset_hash, result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(Uuid::now_v7())
            .bind(tenant)
            .bind(id)
            .bind(&c.device_type)
            .bind(c.confidence)
            .bind(&c.source)
            .bind(&c.ruleset_hash)
            .bind(serde_json::to_value(&c).unwrap_or_default())
            .execute(&mut **tx)
            .await?;
        if !created {
            change(tx, tenant, id, "classification_changed", json!({ "from": prev_type, "to": c.device_type, "confidence": c.confidence, "tier": c.tier }), "system").await?;
        }
    }
    if let Some(fw) = &c.firmware {
        sqlx::query("INSERT INTO firmware_records (tenant_id, asset_id, firmware) VALUES ($1,$2,$3) ON CONFLICT (tenant_id, asset_id, firmware) DO UPDATE SET last_seen = now()")
            .bind(tenant)
            .bind(id)
            .bind(fw)
            .execute(&mut **tx)
            .await?;
        if prev_fw.as_deref().map(|p| p != fw).unwrap_or(false) {
            change(tx, tenant, id, "firmware_changed", json!({ "from": prev_fw, "to": fw }), "system").await?;
            raise_alert(tx, tenant, "firmware_change", &format!("fw:{id}:{fw}"), 5, "device firmware changed", json!({ "asset_id": id, "from": prev_fw, "to": fw })).await?;
        }
    }
    let info = taxonomy::get(&c.device_type);
    // Protocols and services (inventory columns).
    let mut protocols: BTreeSet<String> = BTreeSet::new();
    let mut services: BTreeSet<String> = BTreeSet::new();
    let mut cleartext_creds: BTreeSet<String> = BTreeSet::new();
    let mut opcua_insecure = false;
    for sg in &signals {
        match sg {
            Signal::Protocol { event, .. } => {
                protocols.insert(event.protocol.as_str().to_string());
                if event.details.get("insecure").map(|v| v == "true").unwrap_or(false) {
                    opcua_insecure = true;
                }
            }
            Signal::Service { transport, port } => {
                services.insert(format!("{transport}:{port}"));
            }
            Signal::CleartextCredentials { protocol } => {
                cleartext_creds.insert(protocol.clone());
            }
            _ => {}
        }
    }
    for f in &flows {
        if let Some(p) = f.protocol {
            protocols.insert(p.as_str().to_string());
        }
        if !f.outbound {
            services.insert(format!("{}:{}", f.transport, f.port));
        }
    }
    let served_cleartext: Vec<String> =
        protocols.iter().filter(|p| iot_core::protocols::Protocol::parse(p).map(|x| x.is_cleartext() && x.is_industrial()).unwrap_or(false)).cloned().collect();
    // Findings.
    let feed = state.feed();
    let findings: Vec<Finding> = vuln::assess(
        feed.as_ref(),
        &ExposureInput {
            vendor: c.vendor.as_deref(),
            model: c.model.as_deref(),
            firmware: c.firmware.as_deref(),
            cleartext_protocols: served_cleartext,
            cleartext_credentials: cleartext_creds.into_iter().collect(),
            services: services.iter().cloned().collect(),
            opcua_insecure,
            now: now.date_naive(),
        },
    );
    for f in &findings {
        let (fid, inserted): (Uuid, bool) = sqlx::query_as(
            "INSERT INTO findings (id, tenant_id, asset_id, kind, key, title, severity, known_exploited, detail, remediation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
             ON CONFLICT (tenant_id, asset_id, key) DO UPDATE SET last_seen = now(), title = EXCLUDED.title, severity = EXCLUDED.severity, detail = EXCLUDED.detail,
                status = CASE WHEN findings.status = 'resolved' THEN 'open' ELSE findings.status END
             RETURNING id, (xmax = 0)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(id)
        .bind(f.kind.as_str())
        .bind(&f.key)
        .bind(&f.title)
        .bind(f.severity)
        .bind(f.known_exploited)
        .bind(&f.detail)
        .bind(&f.remediation)
        .fetch_one(&mut **tx)
        .await?;
        if inserted {
            log(
                tx,
                tenant,
                "iot_finding",
                "detect",
                Some(id),
                None,
                json!({ "asset_id": id.to_string(), "finding_id": fid.to_string(), "kind": f.kind.as_str(), "key": f.key, "severity": f.severity }),
            )
            .await?;
        }
    }
    // Findings that no longer apply are resolved (feed or firmware changed).
    let keys: Vec<String> = findings.iter().map(|f| f.key.clone()).collect();
    sqlx::query("UPDATE findings SET status = 'resolved', resolved_at = now() WHERE asset_id = $1 AND status <> 'resolved' AND NOT (key = ANY($2)) AND kind <> 'manual'")
        .bind(id)
        .bind(&keys)
        .execute(&mut **tx)
        .await?;
    // Baseline and anomalies.
    let brow: Option<(Value,)> = sqlx::query_as("SELECT data FROM baselines WHERE asset_id = $1 FOR UPDATE").bind(id).fetch_optional(&mut **tx).await?;
    let mut base: Baseline = brow.and_then(|b| serde_json::from_value(b.0).ok()).unwrap_or_else(|| Baseline::new(now));
    let completed = base.maybe_complete(now, &tc.learning);
    let dctx = DetectContext {
        engineering_station: row["engineering_station"].as_bool().unwrap_or(false) || c.device_type == "engineering_workstation",
        scanner: row["scanner"].as_bool().unwrap_or(false),
        safety_sensitive: info.safety_sensitive,
        engineering_peers: &[],
        threat_indicators: Some(&tc.threats),
        malformed: 0,
        protocol_errors: events.iter().filter(|(e, _)| e.is_error).count() as u64,
    };
    let found = baseline::detect(&mut base, new_flows, events, &dctx, now);
    sqlx::query(
        "INSERT INTO baselines (tenant_id, asset_id, data, network_mode, process_mode, updated_at) VALUES ($1,$2,$3,$4,$5,now())
         ON CONFLICT (tenant_id, asset_id) DO UPDATE SET data = EXCLUDED.data, network_mode = EXCLUDED.network_mode, process_mode = EXCLUDED.process_mode, updated_at = now()",
    )
    .bind(tenant)
    .bind(id)
    .bind(serde_json::to_value(&base).unwrap_or_default())
    .bind(if base.network_mode == baseline::Mode::Learning { "learning" } else { "monitoring" })
    .bind(if base.process_mode == baseline::Mode::Learning { "learning" } else { "monitoring" })
    .execute(&mut **tx)
    .await?;
    if completed {
        sqlx::query("INSERT INTO baseline_snapshots (id, tenant_id, asset_id, reason, data) VALUES ($1,$2,$3,'learning completed',$4)")
            .bind(Uuid::now_v7())
            .bind(tenant)
            .bind(id)
            .bind(serde_json::to_value(&base).unwrap_or_default())
            .execute(&mut **tx)
            .await?;
        change(tx, tenant, id, "baseline_completed", json!({ "edges": base.edges.len() }), "system").await?;
    }
    let mut new_anomalies = 0;
    for a in &found {
        let (aid, inserted): (Uuid, bool) = sqlx::query_as(
            "INSERT INTO anomalies (id, tenant_id, asset_id, kind, key, severity, title, evidence) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (tenant_id, asset_id, key) WHERE status = 'open' DO UPDATE SET count = anomalies.count + 1, last_seen = now(), evidence = EXCLUDED.evidence,
                severity = greatest(anomalies.severity, EXCLUDED.severity)
             RETURNING id, (xmax = 0)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(id)
        .bind(a.kind.as_str())
        .bind(&a.key)
        .bind(a.severity)
        .bind(&a.title)
        .bind(&a.evidence)
        .fetch_one(&mut **tx)
        .await?;
        if inserted {
            new_anomalies += 1;
            log(
                tx,
                tenant,
                "iot_anomaly",
                "alert",
                Some(id),
                None,
                json!({ "asset_id": id.to_string(), "anomaly_id": aid.to_string(), "kind": a.kind.as_str(), "severity": a.severity, "device_type": c.device_type }),
            )
            .await?;
            events::emit_simple(tx, ctx, "iot_anomaly", "detected", aid, Some(1), json!({ "asset_id": id, "kind": a.kind.as_str(), "severity": a.severity, "title": a.title }))
                .await?;
        }
    }
    // Risk.
    let (open_anoms, max_sev): (i64, Option<f64>) =
        sqlx::query_as("SELECT count(*), max(severity) FROM anomalies WHERE asset_id = $1 AND status = 'open'").bind(id).fetch_one(&mut **tx).await?;
    let open_findings: Vec<(Value,)> = sqlx::query_as(
        "SELECT jsonb_build_object('kind', kind, 'key', key, 'title', title, 'severity', severity, 'known_exploited', known_exploited, 'detail', detail) FROM findings WHERE asset_id = $1 AND status = 'open'",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    let finding_list: Vec<Finding> = open_findings.into_iter().filter_map(|f| serde_json::from_value(f.0).ok()).collect();
    let public = |ip: &str| ip.parse::<std::net::IpAddr>().map(|i| risk::is_public(&i)).unwrap_or(false);
    let internet_inbound = flows.iter().any(|f| !f.outbound && public(&f.peer_ip));
    let internet_out: BTreeSet<&str> = flows.iter().filter(|f| f.outbound && public(&f.peer_ip)).map(|f| f.peer_ip.as_str()).collect();
    let modifying_peers: BTreeSet<&str> = flows.iter().filter(|f| !f.outbound && f.max_op.map(|o| o.is_modifying()).unwrap_or(false)).map(|f| f.peer_ip.as_str()).collect();
    let engineering_ops = flows.iter().any(|f| f.outbound && f.max_op.map(|o| o >= OpClass::Program).unwrap_or(false));
    let threat_hits: Vec<String> = flows.iter().filter(|f| tc.threats.contains(&f.peer_ip.to_ascii_lowercase())).map(|f| f.peer_ip.clone()).collect();
    let rs = risk::score(
        &risk::RiskInput {
            device_type: c.device_type.clone(),
            classification_confidence: c.confidence,
            randomized_mac: row["randomized_mac"].as_bool().unwrap_or(false),
            criticality: row["criticality"].as_i64().map(|x| x.clamp(1, 5) as u8),
            findings: finding_list,
            open_anomalies: open_anoms as u32,
            anomaly_severity: max_sev.unwrap_or(0.0),
            internet_inbound,
            internet_outbound_peers: internet_out.len() as u32,
            modifying_peers: modifying_peers.len() as u32,
            issues_engineering_ops: engineering_ops,
            threat_hits,
        },
        &tc.tuning,
    );
    let prev_level = s(&row, "risk_level").unwrap_or_else(|| "low".into());
    let prev_score = row["risk_score"].as_i64().unwrap_or(0);
    if rs.level != prev_level || (rs.score as i64 - prev_score).abs() >= 10 || created {
        sqlx::query("INSERT INTO risk_history (id, tenant_id, asset_id, score, level, factors, model_version) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(Uuid::now_v7())
            .bind(tenant)
            .bind(id)
            .bind(rs.score as i32)
            .bind(&rs.level)
            .bind(serde_json::to_value(&rs.factors).unwrap_or_default())
            .bind(&rs.model_version)
            .execute(&mut **tx)
            .await?;
        log(
            tx,
            tenant,
            "iot_risk",
            "score",
            Some(id),
            None,
            json!({ "asset_id": id.to_string(), "score": rs.score, "level": rs.level, "previous_level": prev_level, "priority": rs.priority }),
        )
        .await?;
        if rs.score as i64 >= 40 || prev_score >= 40 {
            let name = s(&row, "name").or(s(&row, "hostname")).or(mac.clone()).or(s(&row, "ip")).unwrap_or_else(|| id.to_string());
            signal(
                tx,
                tenant,
                json!({ "subject_type": "workload", "subject_name": format!("iot:{name}"), "source": "aether-iot-ot", "category": "iot_device_risk", "score": rs.score, "confidence": c.confidence.clamp(0.0, 1.0),
                        "ttl_secs": 86_400, "details": { "asset_id": id, "device_type": c.device_type, "level": rs.level, "factors": rs.factors.iter().map(|f| f.key.clone()).collect::<Vec<_>>() } }),
            )
            .await?;
        }
    }
    // Segment assignment (dynamic segmentation).
    let facts_d = DeviceFacts {
        id: id.to_string(),
        device_type: c.device_type.clone(),
        category: c.category.clone(),
        vendor: c.vendor.clone(),
        model: c.model.clone(),
        site: s(&row, "site_id"),
        tags: row["tags"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        risk_level: Some(rs.level.clone()),
        confidence: c.confidence,
        quarantined: row["quarantined"].as_bool().unwrap_or(false),
        pinned_groups: row["pinned_group_ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
    };
    let asg = segmentation::assign(&facts_d, &tc.groups, &tc.zones);
    let gids: Vec<Uuid> = asg.groups.iter().filter_map(|g| Uuid::parse_str(g).ok()).collect();
    let zone: Option<Uuid> = asg.zone.as_deref().and_then(|z| Uuid::parse_str(z).ok());
    let prev_groups: Vec<String> = row["group_ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let mut pg = prev_groups.clone();
    pg.sort();
    let mut ng: Vec<String> = gids.iter().map(|g| g.to_string()).collect();
    ng.sort();
    if pg != ng || s(&row, "zone_id") != zone.map(|z| z.to_string()) {
        change(tx, tenant, id, "segment_changed", json!({ "from_groups": prev_groups, "to_groups": ng, "zone_id": zone, "reasons": asg.reasons }), "system").await?;
    }
    sqlx::query(
        "UPDATE assets SET device_type = $2, category = $3, vendor = $4, model = $5, os = $6, firmware = $7, confidence = $8, tier = $9, classification = $10,
             protocols = $11, services = $12, risk_score = $13, risk_level = $14, impact = $15, priority = $16, risk = $17, risk_evaluated_at = now(),
             group_ids = $18, zone_id = $19, assignment = $20, updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(&c.device_type)
    .bind(&c.category)
    .bind(&c.vendor)
    .bind(&c.model)
    .bind(&c.os)
    .bind(&c.firmware)
    .bind(c.confidence)
    .bind(&c.tier)
    .bind({
        let mut v = serde_json::to_value(&c).unwrap_or_default();
        v["behaviour"] = json!(facts.iter().filter(|f| f.source == "behaviour").map(|f| format!("{}={}", f.field, f.value)).collect::<Vec<_>>());
        v
    })
    .bind(protocols.into_iter().collect::<Vec<_>>())
    .bind(services.into_iter().collect::<Vec<_>>())
    .bind(rs.score as i32)
    .bind(&rs.level)
    .bind(rs.impact as i32)
    .bind(rs.priority as i32)
    .bind(serde_json::to_value(&rs).unwrap_or_default())
    .bind(&gids)
    .bind(zone)
    .bind(json!({ "reasons": asg.reasons, "withheld": asg.withheld }))
    .execute(&mut **tx)
    .await?;
    if created {
        log(
            tx,
            tenant,
            "iot_discovery",
            "discover",
            Some(id),
            None,
            json!({ "asset_id": id.to_string(), "mac": mac, "ip": s(&row, "ip"), "device_type": c.device_type, "category": c.category, "vendor": c.vendor, "model": c.model, "confidence": c.confidence,
                    "site_id": s(&row, "site_id"), "sensor_id": s(&row, "last_sensor_id"), "event": "discovered" }),
        )
        .await?;
        events::emit_simple(tx, ctx, "iot_asset", "discovered", id, Some(1), json!({ "id": id, "device_type": c.device_type, "category": c.category, "confidence": c.confidence }))
            .await?;
    }
    Ok(new_anomalies)
}

/// Re-evaluate assets without new observations (rule or override change,
/// feed refresh, learning completion). Returns the number evaluated.
pub async fn reevaluate(state: &AppState, tenant: Uuid, ids: &[Uuid]) -> ApiResult<usize> {
    let tc = tenant_ctx(state, tenant).await?;
    let ctx = Ctx::system(state.pool.clone(), crate::state::SERVICE_NAME, tenant, Uuid::now_v7().to_string());
    let mut n = 0;
    for id in ids {
        let mut tx = ctx.tx().await?;
        evaluate(state, &ctx, &mut tx, &tc, *id, &[], &[], false).await?;
        tx.commit().await?;
        n += 1;
    }
    Ok(n)
}

/// Facts → hashmap helper used by the API (explain).
pub fn explain(c: &Value) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for k in [
        "device_type",
        "category",
        "vendor",
        "model",
        "os",
        "firmware",
        "confidence",
        "tier",
        "evidence",
        "conflicts",
        "classifier_version",
        "ruleset_hash",
        "source",
        "dimensions",
        "behaviour",
    ] {
        m.insert(k.to_string(), c.get(k).cloned().unwrap_or(Value::Null));
    }
    m
}

/// Lifecycle helper: mark assets not seen within `days` as inactive.
pub async fn mark_inactive(tx: &mut Tx, days: i64) -> ApiResult<u64> {
    let r = sqlx::query("UPDATE assets SET lifecycle = 'inactive', updated_at = now() WHERE lifecycle IN ('active', 'discovered') AND last_seen < now() - make_interval(days => $1) AND merged_into IS NULL")
        .bind(days as i32)
        .execute(&mut **tx)
        .await?;
    Ok(r.rows_affected())
}

pub fn lifecycle_ok(from: &str, to: &str) -> bool {
    match (Lifecycle::parse(from), Lifecycle::parse(to)) {
        (Some(a), Some(b)) => a.can_move_to(b),
        _ => false,
    }
}

pub fn strength_label(s: Option<Strength>) -> &'static str {
    match s {
        Some(Strength::Strong) => "strong",
        Some(Strength::Medium) => "medium",
        Some(Strength::Weak) => "weak",
        None => "none",
    }
}
