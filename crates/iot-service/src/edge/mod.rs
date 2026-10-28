//! Edge appliance: passive collector and segmentation enforcer enrolled as
//! an Aether node (ZTE-IOT sections 3 Site And Sensor Topology, 4 Passive
//! Discovery, 6 Packet Metadata Collection, 74/76–78 enforcement, 81
//! Branch Enforcement, 82 Cloud Policy Distribution, 117 Sensor/Collector
//! Security, 122 HA/DR; ZTE-IOTINV-153167 fail static; docs/integration.md
//! §6).
//!
//! 1. Enrols once with a provisioning key (credential stored 0600) and
//!    exchanges it for short-lived node tokens.
//! 2. Heartbeats with health, load, applied configuration version and the
//!    active failure modes; follows platform upgrade instructions by
//!    reporting them (the host's package manager performs upgrades).
//! 3. Polls the platform manifest (`If-None-Match`), fetches the
//!    `iot.segmentation` artifacts, verifies each content hash against the
//!    manifest and its self-hash, fetches the product snapshot (zones,
//!    groups, device memberships, approved exceptions and active queries)
//!    and verifies its hash; then swaps the runtime atomically, persists it
//!    and acknowledges (or reports the error and keeps the last good one).
//! 4. Captures mirrored traffic (pcap spool directory, TZSP over UDP) into
//!    the collector and ships observation batches (bounded queue, retries,
//!    idempotent batch ids) — passive only.
//! 5. Decides flows for local enforcement points (`POST /v1/decide`),
//!    aggregates decisions, renders nftables rules, executes approved safe
//!    active queries.
//!
//! On restart the persisted configuration is enforced before the platform
//! is reachable; losing the platform never collapses segmentation.

pub mod activeq;
pub mod admin;
pub mod capture;

use crate::config::EdgeConfig;
use crate::platform::{PResult, Platform, PlatformError};
use aether_core::policy::compile::{BundleManifest, CompiledPolicy};
use aether_core::policy::eval::PreparedPolicy;
use anyhow::{anyhow, bail, Context as _, Result};
use chrono::{DateTime, Utc};
use iot_core::collect::Collector;
use iot_core::policy::{DeviceCtx, FlowCtx};
use iot_core::segmentation::{self, Exception, Mode, Verdict, Zone};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CAPABILITIES: &[&str] = &["iot_collector", "iot_enforcer", "pcap_spool", "tzsp", "active_queries"];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credential {
    node_id: Uuid,
    tenant_id: Uuid,
    credential: String,
}

/// The configuration the edge enforces; swapped atomically.
pub struct Runtime {
    pub policy: Option<Arc<PreparedPolicy>>,
    pub config_version: i64,
    pub suspended: bool,
    pub snapshot: Value,
    pub revision: i64,
    pub zones: Vec<Zone>,
    pub exceptions: Vec<Exception>,
    pub devices_by_ip: HashMap<String, DeviceCtx>,
    pub loaded_at: DateTime<Utc>,
}

impl Runtime {
    pub fn empty() -> Runtime {
        Runtime {
            policy: None,
            config_version: 0,
            suspended: false,
            snapshot: Value::Null,
            revision: 0,
            zones: vec![],
            exceptions: vec![],
            devices_by_ip: HashMap::new(),
            loaded_at: Utc::now(),
        }
    }

    /// Build from verified artifacts and a verified snapshot document.
    pub fn build(config_version: i64, suspended: bool, artifacts: &[CompiledPolicy], snapshot: Value) -> Runtime {
        let policy = artifacts.iter().find(|a| a.policy_type == iot_core::policy::SEGMENTATION).cloned().map(|c| Arc::new(PreparedPolicy::new(c)));
        let zones: Vec<Zone> = snapshot["zones"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|z| Zone {
                id: z["id"].as_str().unwrap_or_default().into(),
                key: z["key"].as_str().unwrap_or_default().into(),
                security_level: z["security_level"].as_u64().unwrap_or(2).clamp(1, 4) as u8,
                mode: Mode::parse(z["mode"].as_str().unwrap_or("observe")).unwrap_or(Mode::Observe),
                safety_critical: z["safety_critical"].as_bool().unwrap_or(false),
            })
            .collect();
        let exceptions: Vec<Exception> = snapshot["exceptions"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|e| serde_json::from_value(e).ok()).collect();
        let mut devices_by_ip = HashMap::new();
        for d in snapshot["devices"].as_array().cloned().unwrap_or_default() {
            let Some(ip) = d["ip"].as_str() else { continue };
            let ty = d["device_type"].as_str().map(String::from);
            let ctx = DeviceCtx {
                device_id: d["id"].as_str().map(String::from),
                groups: d["groups"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
                zone: d["zone"].as_str().map(String::from),
                site: d["site"].as_str().map(String::from),
                safety_sensitive: ty.as_deref().map(|t| iot_core::taxonomy::get(t).safety_sensitive).unwrap_or(false),
                device_type: ty,
                category: d["category"].as_str().map(String::from),
                risk_level: d["risk_level"].as_str().map(String::from),
                confidence_tier: d["tier"].as_str().map(String::from),
                quarantined: d["quarantined"].as_bool().unwrap_or(false),
                ip: Some(ip.to_string()),
                evaluated_at: d["evaluated_at"].as_str().and_then(|t| t.parse().ok()),
            };
            devices_by_ip.insert(ip.to_string(), ctx);
        }
        Runtime { policy, config_version, suspended, revision: snapshot["revision"].as_i64().unwrap_or(0), snapshot, zones, exceptions, devices_by_ip, loaded_at: Utc::now() }
    }

    pub fn device(&self, ip: &str) -> DeviceCtx {
        self.devices_by_ip.get(ip).cloned().unwrap_or_else(|| DeviceCtx { ip: Some(ip.to_string()), ..Default::default() })
    }

    /// Decide a flow. Suspended enforcement allows and observes (OT
    /// processes are never cut by a suspended tenant configuration).
    pub fn decide(&self, src_ip: &str, dst_ip: &str, protocol: Option<&str>, op: Option<&str>, port: Option<u16>, at: DateTime<Utc>) -> Verdict {
        let dst = self.device(dst_ip);
        let internet = dst.device_id.is_none() && dst_ip.parse::<std::net::IpAddr>().map(|i| iot_core::risk::is_public(&i)).unwrap_or(false);
        let f = FlowCtx {
            source: self.device(src_ip),
            destination: dst,
            protocol: protocol.map(String::from),
            operation_class: op.map(String::from),
            operation: None,
            port,
            internet,
            at: Some(at),
        };
        let mut v = segmentation::decide(self.policy.as_deref(), &self.exceptions, &self.zones, &f, at);
        if self.suspended && v.enforced == "block" {
            v.enforced = "allow".into();
            v.reason = format!("enforcement suspended; {}", v.reason);
        }
        v
    }
}

#[derive(Serialize, Deserialize)]
struct Applied {
    config_version: i64,
    suspended: bool,
    artifacts: Vec<Value>,
    snapshot: Value,
}

/// Aggregated decisions waiting to be reported.
#[derive(Default)]
pub struct DecisionStats {
    m: Mutex<BTreeMap<(String, String, String, Option<String>, Option<String>), (u64, Value)>>,
}

impl DecisionStats {
    pub fn record(&self, v: &Verdict, src: &DeviceCtx, dst: &DeviceCtx, protocol: Option<&str>, op: Option<&str>) {
        let mut g = self.m.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= 10_000 {
            return;
        }
        let rule = v.rule_name.clone().or_else(|| v.exception_id.as_ref().map(|e| format!("exception:{e}"))).unwrap_or_else(|| "default".into());
        let key = (rule.clone(), v.enforced.clone(), v.policy_action.clone(), src.device_id.clone(), dst.device_id.clone());
        let e = g.entry(key).or_insert((
            0,
            json!({ "rule": rule, "enforced": v.enforced, "policy_action": v.policy_action, "mode": format!("{:?}", v.mode).to_ascii_lowercase(),
            "source_asset": src.device_id, "destination_asset": dst.device_id, "protocol": protocol, "operation_class": op }),
        ));
        e.0 += 1;
    }
    pub fn drain(&self) -> Vec<Value> {
        let mut g = self.m.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *g)
            .into_values()
            .map(|(n, mut v)| {
                v["count"] = json!(n);
                v
            })
            .collect()
    }
}

pub struct Agent {
    pub cfg: EdgeConfig,
    pub platform: Platform,
    pub node_id: Uuid,
    pub tenant_id: Uuid,
    credential: String,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
    runtime: RwLock<Arc<Runtime>>,
    config_etag: tokio::sync::Mutex<Option<String>>,
    snapshot_etag: tokio::sync::Mutex<Option<String>>,
    pub collector: Mutex<Collector>,
    /// Observation batches waiting to be shipped (bounded, oldest dropped).
    pub queue: Mutex<VecDeque<Value>>,
    pub dropped_batches: AtomicU64,
    pub shipped_batches: AtomicU64,
    pub decisions: DecisionStats,
    last_sync_ms: AtomicI64,
    pub started_at: DateTime<Utc>,
    pub metrics: aether_kit::metrics::Metrics,
    pub parser_panics: AtomicU64,
    /// Last applied nftables document.
    pub nft: Mutex<String>,
    pub cloud_reachable: std::sync::atomic::AtomicBool,
    pub upgrade: Mutex<Option<Value>>,
    pub clock_skew_secs: AtomicI64,
    pub sync_now: tokio::sync::Notify,
    /// Active queries already executed (by id).
    pub queries_done: Mutex<std::collections::HashSet<String>>,
}

fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn enroll(platform: &Platform, cfg: &EdgeConfig) -> Result<Credential> {
    let key = cfg.provisioning_key.clone().context("no stored node credential and IOT_PROVISIONING_KEY is not set")?;
    let body = json!({ "provisioning_key": key, "name": cfg.name, "software_version": SOFTWARE_VERSION, "platform": std::env::consts::OS, "capabilities": CAPABILITIES });
    let v = platform.call(Method::POST, "/api/v1/nodes/enroll", None, Some(&body)).await.map_err(|e| anyhow!("enrolment failed: {e}"))?;
    let d = &v["data"];
    Ok(Credential {
        node_id: d["node_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()).context("enrolment response without node_id")?,
        tenant_id: d["tenant_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()).context("enrolment response without tenant_id")?,
        credential: d["credential"].as_str().context("enrolment response without credential")?.to_string(),
    })
}

impl Agent {
    fn new(cfg: EdgeConfig, platform: Platform, cred: Credential) -> Agent {
        Agent {
            platform,
            node_id: cred.node_id,
            tenant_id: cred.tenant_id,
            credential: cred.credential,
            token: tokio::sync::Mutex::new(None),
            runtime: RwLock::new(Arc::new(Runtime::empty())),
            config_etag: tokio::sync::Mutex::new(None),
            snapshot_etag: tokio::sync::Mutex::new(None),
            collector: Mutex::new(Collector::default()),
            queue: Mutex::new(VecDeque::new()),
            dropped_batches: AtomicU64::new(0),
            shipped_batches: AtomicU64::new(0),
            decisions: DecisionStats::default(),
            last_sync_ms: AtomicI64::new(0),
            started_at: Utc::now(),
            metrics: aether_kit::metrics::Metrics::new("aether_iot_edge"),
            parser_panics: AtomicU64::new(0),
            nft: Mutex::new(String::new()),
            cloud_reachable: std::sync::atomic::AtomicBool::new(true),
            upgrade: Mutex::new(None),
            clock_skew_secs: AtomicI64::new(0),
            sync_now: tokio::sync::Notify::new(),
            queries_done: Mutex::new(Default::default()),
            cfg,
        }
    }

    /// Load or create the node identity, restore the persisted
    /// configuration and perform a first sync.
    pub async fn start(cfg: EdgeConfig) -> Result<Arc<Agent>> {
        let platform = Platform::new(&cfg.platform)?;
        let dir = std::path::PathBuf::from(&cfg.state_dir);
        std::fs::create_dir_all(&dir).with_context(|| format!("cannot create state directory {}", dir.display()))?;
        let cred_path = dir.join("credential.json");
        let cred: Credential = match std::fs::read(&cred_path) {
            Ok(b) => serde_json::from_slice(&b).context("corrupt node credential file")?,
            Err(_) => {
                let c = enroll(&platform, &cfg).await?;
                write_private(&cred_path, &serde_json::to_vec(&c)?)?;
                tracing::info!(node_id = %c.node_id, "edge node enrolled");
                c
            }
        };
        let agent = Arc::new(Agent::new(cfg, platform, cred));
        if let Err(e) = agent.restore() {
            tracing::warn!(error = %e, "no usable persisted configuration");
        }
        if let Err(e) = agent.sync_config().await {
            tracing::warn!(error = %format!("{e:#}"), "initial configuration sync failed; enforcing the persisted configuration");
        }
        Ok(agent)
    }

    /// An agent without platform identity (offline analysis, tests).
    pub fn offline(cfg: EdgeConfig, runtime: Runtime) -> Result<Arc<Agent>> {
        let platform = Platform::new(&cfg.platform)?;
        let a = Agent::new(cfg, platform, Credential { node_id: Uuid::nil(), tenant_id: Uuid::nil(), credential: String::new() });
        a.swap(runtime);
        Ok(Arc::new(a))
    }

    pub fn runtime(&self) -> Arc<Runtime> {
        self.runtime.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn swap(&self, rt: Runtime) {
        self.metrics.set("config_version", rt.config_version);
        self.metrics.set("config_revision", rt.revision);
        *self.runtime.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(rt);
    }

    fn state_path(&self, f: &str) -> std::path::PathBuf {
        std::path::Path::new(&self.cfg.state_dir).join(f)
    }

    fn restore(&self) -> Result<()> {
        let a: Applied = serde_json::from_slice(&std::fs::read(self.state_path("applied.json"))?)?;
        let mut arts = vec![];
        for v in a.artifacts {
            arts.push(CompiledPolicy::from_json_verified(v).map_err(|e| anyhow!("persisted artifact: {e}"))?);
        }
        if !crate::api::ingest::verify_snapshot(&a.snapshot) {
            bail!("persisted snapshot failed verification");
        }
        self.swap(Runtime::build(a.config_version, a.suspended, &arts, a.snapshot));
        tracing::info!(config_version = a.config_version, "restored the last applied configuration");
        Ok(())
    }

    pub async fn node_token(&self) -> PResult<String> {
        let mut g = self.token.lock().await;
        if let Some((t, exp)) = g.as_ref() {
            if *exp > Instant::now() + Duration::from_secs(60) {
                return Ok(t.clone());
            }
        }
        let v = self.platform.call(Method::POST, "/api/v1/nodes/token", None, Some(&json!({ "credential": self.credential }))).await?;
        let t = v["access_token"].as_str().ok_or_else(|| PlatformError::Decode("no access_token".into()))?.to_string();
        let exp = v["expires_at"].as_i64().unwrap_or(0);
        let ttl = (exp - Utc::now().timestamp()).clamp(60, 3600) as u64;
        // Clock skew: the token lifetime is 15 minutes by contract.
        if exp > 0 {
            self.clock_skew_secs.store((exp - 900) - Utc::now().timestamp(), Ordering::Relaxed);
        }
        *g = Some((t.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(t)
    }

    /// Call as this node, renewing the token once on 401.
    pub async fn node_send(&self, method: Method, url: &str, body: Option<&Value>, headers: &[(&str, String)], idempotent: bool) -> PResult<reqwest::Response> {
        if self.credential.is_empty() {
            return Err(PlatformError::NotConfigured("node credential (offline agent)"));
        }
        for attempt in 0..2 {
            let token = self.node_token().await?;
            let res = self.platform.send(method.clone(), url, Some(&token), body, headers, idempotent).await;
            match &res {
                Ok(r) if r.status() == StatusCode::UNAUTHORIZED && attempt == 0 => {
                    *self.token.lock().await = None;
                    continue;
                }
                Ok(_) => self.cloud_reachable.store(true, Ordering::Relaxed),
                Err(PlatformError::Transport(_)) => self.cloud_reachable.store(false, Ordering::Relaxed),
                Err(_) => {}
            }
            return res;
        }
        unreachable!("loop returns")
    }

    async fn node_json(&self, method: Method, url: &str, body: Option<&Value>) -> PResult<Value> {
        let idem = method == Method::GET;
        let res = self.node_send(method, url, body, &[], idem).await?;
        let status = res.status().as_u16();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if !(200..300).contains(&status) {
            return Err(PlatformError::Status {
                status,
                code: v["code"].as_str().unwrap_or("error").into(),
                detail: v["detail"].as_str().unwrap_or("").chars().take(300).collect(),
            });
        }
        Ok(v)
    }

    fn mark_synced(&self) {
        self.last_sync_ms.store(Utc::now().timestamp_millis(), Ordering::Relaxed);
    }

    pub fn config_age_secs(&self) -> Option<i64> {
        let l = self.last_sync_ms.load(Ordering::Relaxed);
        (l > 0).then(|| (Utc::now().timestamp_millis() - l) / 1000)
    }

    /// One configuration poll: platform manifest + product snapshot.
    /// Returns true when a new configuration was applied.
    pub async fn sync_config(&self) -> Result<bool> {
        let etag = self.config_etag.lock().await.clone();
        let headers: Vec<(&str, String)> = etag.clone().map(|e| vec![("if-none-match", e)]).unwrap_or_default();
        let res = self.node_send(Method::GET, "/api/v1/node/config", None, &headers, true).await?;
        let snap_url = format!("{}/api/v1/node/snapshot", self.cfg.control_url);
        let s_etag = self.snapshot_etag.lock().await.clone();
        let s_headers: Vec<(&str, String)> = s_etag.clone().map(|e| vec![("if-none-match", e)]).unwrap_or_default();
        let sres = self.node_send(Method::GET, &snap_url, None, &s_headers, true).await?;
        let rt = self.runtime();
        let new_snapshot: Option<(Value, Option<String>)> = match sres.status() {
            StatusCode::NOT_MODIFIED => None,
            s if s.is_success() => {
                let et = sres.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(String::from);
                let v: Value = sres.json().await?;
                let doc = v["data"].clone();
                if !crate::api::ingest::verify_snapshot(&doc) || doc["tenant_id"].as_str() != Some(&self.tenant_id.to_string()) {
                    bail!("product snapshot failed verification");
                }
                Some((doc, et))
            }
            s => bail!("snapshot request failed with {s}"),
        };
        if res.status() == StatusCode::NOT_MODIFIED {
            self.mark_synced();
            if let Some((doc, et)) = new_snapshot {
                let arts: Vec<CompiledPolicy> = rt.policy.iter().map(|p| p.policy.clone()).collect();
                self.apply(rt.config_version, rt.suspended, arts, doc)?;
                *self.snapshot_etag.lock().await = et;
                return Ok(true);
            }
            return Ok(false);
        }
        if !res.status().is_success() {
            bail!("configuration request failed with {}", res.status());
        }
        let new_etag = res.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(String::from);
        let v: Value = res.json().await?;
        let d = &v["data"];
        let cv = d["config_version"].as_i64().unwrap_or(0);
        let suspended = d["enforcement"].as_str().map(|e| e != "enabled").unwrap_or(false);
        let outcome: Result<()> = async {
            let mut artifacts = vec![];
            if !d["manifest"].is_null() {
                let m: BundleManifest = serde_json::from_value(d["manifest"].clone()).context("invalid manifest")?;
                if !m.verify() || m.config_version != cv || m.tenant_id != self.tenant_id {
                    bail!("manifest failed verification");
                }
                for e in m.entries.iter().filter(|e| e.policy_type.starts_with("iot.")) {
                    let a = self.node_json(Method::GET, &format!("/api/v1/node/artifacts/{}/{}", e.policy_set_id, e.revision), None).await.map_err(|x| anyhow!("{x}"))?;
                    let c = CompiledPolicy::from_json_verified(a["data"].clone()).map_err(|x| anyhow!("artifact {}: {x}", e.policy_set_id))?;
                    if c.content_hash != e.content_hash || c.tenant_id != self.tenant_id {
                        bail!("artifact {} does not match the manifest", e.policy_set_id);
                    }
                    artifacts.push(c);
                }
            }
            let doc = match &new_snapshot {
                Some((d, _)) => d.clone(),
                None if !rt.snapshot.is_null() => rt.snapshot.clone(),
                None => bail!("no product snapshot available"),
            };
            self.apply(cv, suspended, artifacts, doc)
        }
        .await;
        match outcome {
            Ok(()) => {
                self.mark_synced();
                *self.config_etag.lock().await = new_etag;
                if let Some((_, et)) = new_snapshot {
                    *self.snapshot_etag.lock().await = et;
                }
                let _ = self.node_json(Method::POST, "/api/v1/node/ack", Some(&json!({ "config_version": cv }))).await;
                self.metrics.count("config_apply", "ok");
                tracing::info!(config_version = cv, suspended, "configuration applied");
                Ok(true)
            }
            Err(e) => {
                self.metrics.count("config_apply", "error");
                let _ = self.node_json(Method::POST, "/api/v1/node/ack", Some(&json!({ "config_version": cv, "error": format!("{e:#}") }))).await;
                Err(e)
            }
        }
    }

    fn apply(&self, cv: i64, suspended: bool, artifacts: Vec<CompiledPolicy>, snapshot: Value) -> Result<()> {
        let rt = Runtime::build(cv, suspended, &artifacts, snapshot.clone());
        let nft = self.render_nft(&rt);
        self.swap(rt);
        let applied = Applied { config_version: cv, suspended, artifacts: artifacts.iter().map(|a| serde_json::to_value(a).unwrap_or_default()).collect(), snapshot };
        if let Err(e) = write_private(&self.state_path("applied.json"), &serde_json::to_vec(&applied)?) {
            tracing::warn!(error = %e, "could not persist the applied configuration");
        }
        *self.nft.lock().unwrap_or_else(|e| e.into_inner()) = nft.clone();
        if let (Some(p), true) = (&self.cfg.nft_path, self.cfg.enforce) {
            if let Err(e) = std::fs::write(p, &nft) {
                tracing::warn!(error = %e, "could not write nftables rules");
            }
        }
        Ok(())
    }

    /// nftables rules for host enforcement: one address set per device
    /// group and accept rules for approved group-to-group exceptions. The
    /// forward chain policy stays `accept` — the edge never default-drops
    /// OT traffic at the host; blocking happens per flow through the
    /// decision API for zones in enforce mode (quarantined devices are
    /// dropped when enforcement is active).
    pub fn render_nft(&self, rt: &Runtime) -> String {
        let mut members: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        let enforcing = rt.zones.iter().any(|z| z.mode == Mode::Enforce) && rt.policy.is_some() && !rt.suspended;
        for (ip, d) in &rt.devices_by_ip {
            for g in &d.groups {
                members.entry(g.clone()).or_default().insert(ip.clone());
            }
            if d.quarantined && enforcing {
                members.entry(segmentation::QUARANTINE_GROUP.to_string()).or_default().insert(ip.clone());
            }
        }
        // Quarantine drops come first so no exception re-admits a quarantined device.
        let mut rules: Vec<(String, String, String, u16, bool)> = vec![];
        if members.contains_key(segmentation::QUARANTINE_GROUP) {
            for g in members.keys().filter(|g| g.as_str() != segmentation::QUARANTINE_GROUP) {
                for t in ["tcp", "udp"] {
                    rules.push((segmentation::QUARANTINE_GROUP.to_string(), g.clone(), t.to_string(), 0, false));
                }
            }
        }
        rules.extend(rt.exceptions.iter().filter_map(|e| {
            Some((e.source_group.clone()?, e.destination_group.clone()?, if e.protocol.as_deref() == Some("udp") { "udp".to_string() } else { "tcp".to_string() }, e.port?, true))
        }));
        segmentation::render_nftables(&members, &rules, false)
    }

    /// Queue an observation batch (bounded; the oldest batch is dropped).
    pub fn enqueue(&self, batch: Value) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= self.cfg.queue_batches.max(1) {
            q.pop_front();
            self.dropped_batches.fetch_add(1, Ordering::Relaxed);
            self.metrics.count("batch_dropped", "queue_full");
        }
        q.push_back(batch);
    }

    /// Drain the collector into a batch and ship queued batches.
    pub async fn flush(&self) -> Result<usize> {
        let (obs, stats) = {
            let mut c = self.collector.lock().unwrap_or_else(|e| e.into_inner());
            let obs = c.drain(None, Some(&self.node_id.to_string()));
            (obs, serde_json::to_value(&c.stats).unwrap_or_default())
        };
        for chunk in obs.chunks(2000) {
            self.enqueue(json!({ "batch_id": format!("{}-{}", self.node_id, Uuid::now_v7()), "observations": chunk, "stats": stats }));
        }
        let mut shipped = 0;
        loop {
            let next = self.queue.lock().unwrap_or_else(|e| e.into_inner()).front().cloned();
            let Some(b) = next else { break };
            let url = format!("{}/api/v1/node/observations", self.cfg.control_url);
            match self.node_send(Method::POST, &url, Some(&b), &[], true).await {
                Ok(r) if r.status().is_success() => {
                    self.queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
                    self.shipped_batches.fetch_add(1, Ordering::Relaxed);
                    shipped += 1;
                }
                Ok(r) if r.status() == StatusCode::TOO_MANY_REQUESTS || r.status().is_server_error() => break,
                Ok(r) => {
                    // A batch the control plane refuses is dropped (logged) rather than retried forever.
                    let st = r.status();
                    let body = r.text().await.unwrap_or_default();
                    tracing::warn!(status = %st, body = %body.chars().take(300).collect::<String>(), "observation batch refused");
                    self.queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
                    self.dropped_batches.fetch_add(1, Ordering::Relaxed);
                    if st == StatusCode::CONFLICT {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "control plane unreachable; batches stay queued");
                    break;
                }
            }
        }
        Ok(shipped)
    }

    /// Measured health and active failure modes of this edge.
    pub fn health(&self) -> (iot_core::failure::Health, Vec<Value>) {
        let (stats, devices) = {
            let c = self.collector.lock().unwrap_or_else(|e| e.into_inner());
            (c.stats.clone(), c.device_count())
        };
        let _ = devices;
        let qlen = self.queue.lock().unwrap_or_else(|e| e.into_inner()).len();
        let errs: u64 = stats.parse_errors.values().sum();
        let up = (Utc::now() - self.started_at).num_seconds().max(60) as f64 / 60.0;
        let h = iot_core::failure::Health {
            sensor_silent_secs: None,
            capture_drop_ratio: if stats.frames > 0 { stats.decode_errors.values().sum::<u64>() as f64 / stats.frames as f64 } else { 0.0 },
            duplicate_ratio: 0.0,
            ip_changes_last_hour: 0,
            randomized_macs_last_hour: 0,
            ambiguous_devices: 0,
            parser_failures: self.parser_panics.load(Ordering::Relaxed),
            malformed_per_minute: errs as f64 / up,
            branch_reachable: true,
            policy_age_secs: self.config_age_secs(),
            graph_age_secs: None,
            risk_feed_age_secs: None,
            cloud_reachable: self.cloud_reachable.load(Ordering::Relaxed),
            clock_skew_secs: self.clock_skew_secs.load(Ordering::Relaxed),
            backlog_pct: ((qlen * 100) / self.cfg.queue_batches.max(1)).min(100) as u8,
            upgrade_interrupted: false,
        };
        let th = iot_core::failure::Thresholds { policy_stale_secs: self.cfg.config_stale_after.as_secs() as i64, ..Default::default() };
        let active = iot_core::failure::evaluate(&h, &th).into_iter().map(|a| json!({ "mode": a.mode.key, "measured": a.measured })).collect();
        (h, active)
    }

    pub fn status(&self) -> Value {
        let rt = self.runtime();
        let (h, active) = self.health();
        let c = self.collector.lock().unwrap_or_else(|e| e.into_inner());
        json!({
            "node_id": self.node_id, "tenant_id": self.tenant_id, "software_version": SOFTWARE_VERSION, "started_at": self.started_at,
            "config": { "config_version": rt.config_version, "revision": rt.revision, "loaded_at": rt.loaded_at, "confirmed_age_secs": self.config_age_secs(), "policy_loaded": rt.policy.is_some(),
                        "policy_hash": rt.policy.as_ref().map(|p| p.policy.content_hash.clone()), "suspended": rt.suspended, "devices": rt.devices_by_ip.len(), "zones": rt.zones.len(), "exceptions": rt.exceptions.len() },
            "capture": c.stats, "queue": { "batches": self.queue.lock().unwrap_or_else(|e| e.into_inner()).len(), "dropped": self.dropped_batches.load(Ordering::Relaxed), "shipped": self.shipped_batches.load(Ordering::Relaxed) },
            "health": h, "failures": active, "platform": self.platform.health(), "upgrade": *self.upgrade.lock().unwrap_or_else(|e| e.into_inner()),
        })
    }

    async fn heartbeat(&self) -> Result<()> {
        let rt = self.runtime();
        let (_, active) = self.health();
        let qpct = (self.queue.lock().unwrap_or_else(|e| e.into_inner()).len() * 100 / self.cfg.queue_batches.max(1)).min(100) as i64;
        let body = json!({ "software_version": SOFTWARE_VERSION, "health_score": (100 - qpct / 2 - (active.len() as i64 * 5)).clamp(0, 100), "load_pct": qpct, "applied_config_version": rt.config_version,
            "health": { "revision": rt.revision, "failures": active, "policy_loaded": rt.policy.is_some() } });
        let v = self.node_json(Method::POST, "/api/v1/node/heartbeat", Some(&body)).await?;
        if v["data"]["desired_config_version"].as_i64().map(|d| d != rt.config_version).unwrap_or(false) {
            self.sync_now.notify_one();
        }
        if !v["data"]["upgrade"].is_null() {
            // Upgrades are performed by the host package manager; record the instruction for operators.
            *self.upgrade.lock().unwrap_or_else(|e| e.into_inner()) = Some(v["data"]["upgrade"].clone());
        }
        Ok(())
    }

    /// Report status (and decisions) to the product control plane.
    pub async fn report(&self) -> Result<()> {
        let rt = self.runtime();
        let (h, active) = self.health();
        let body = json!({ "software_version": SOFTWARE_VERSION, "config_revision": rt.revision, "health": h, "failures": active, "config_age_secs": self.config_age_secs() });
        self.node_json(Method::POST, &format!("{}/api/v1/node/status", self.cfg.control_url), Some(&body)).await?;
        let d = self.decisions.drain();
        if !d.is_empty() {
            self.node_json(Method::POST, &format!("{}/api/v1/node/decisions", self.cfg.control_url), Some(&Value::Array(d))).await?;
        }
        Ok(())
    }

    pub fn spawn_loops(self: &Arc<Self>) {
        let a = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(a.cfg.heartbeat_interval);
            loop {
                t.tick().await;
                if let Err(e) = a.heartbeat().await {
                    tracing::warn!(error = %e, "heartbeat failed");
                }
                if let Err(e) = a.report().await {
                    tracing::debug!(error = %e, "status report failed");
                }
            }
        });
        let a = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(a.cfg.poll_interval) => {}
                    _ = a.sync_now.notified() => {}
                }
                if let Err(e) = a.sync_config().await {
                    tracing::warn!(error = %format!("{e:#}"), "configuration sync failed; keeping the last verified configuration");
                }
                if let Err(e) = activeq::run_approved(&a).await {
                    tracing::warn!(error = %e, "active query execution failed");
                }
            }
        });
        let a = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(a.cfg.flush_interval);
            let mut n: u64 = 0;
            loop {
                t.tick().await;
                n += 1;
                if n.is_multiple_of(360) {
                    a.collector.lock().unwrap_or_else(|e| e.into_inner()).reset_dedup();
                }
                if let Err(e) = a.flush().await {
                    tracing::warn!(error = %e, "observation flush failed");
                }
            }
        });
        if let Some(dir) = self.cfg.spool_dir.clone() {
            tokio::spawn(capture::run_spool(self.clone(), dir));
        }
        if let Some(bind) = self.cfg.tzsp_bind.clone() {
            tokio::spawn(capture::run_tzsp(self.clone(), bind));
        }
    }
}
