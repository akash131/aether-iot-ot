//! Communication baselines, allow-list learning, drift and anomaly
//! detection (ZTE-IOT sections 52 Protocol Anomaly Detection, 53 Device
//! Communication Baseline, 96 Anomaly Events; Volume 2 "Anomaly Signals";
//! AE-IOT-0001 learning mode with automatic completion, AE-IOT-0002
//! "learned" acknowledgement, AE-IOT-0003 scanner designation, AE-IOT-0009
//! independent network and process learning, AE-IOT-0010 process value
//! ranges, AE-IOT-0013 baseline snapshots and differences, AE-IOT-0030
//! engineering operations, AE-IOT-0031 controller mode changes,
//! AE-IOT-0033 unauthorised engineering stations).
//!
//! A baseline holds, per device, the set of communication **edges**
//! (peer, transport, server port, direction, protocol) with the highest
//! operation class seen and traffic volume, and the learned **value range**
//! of process variables written (register/point → min..max). While a
//! baseline is learning, new edges are absorbed; learning ends after a
//! fixed window or automatically when the rate of new edges falls below a
//! threshold. Afterwards every deviation becomes a typed anomaly with a
//! severity and evidence. Signature-style detections (controller stop,
//! program download, scans, malformed protocol bursts) fire in any mode.

use crate::model::Flow;
use crate::protocols::{OpClass, ProtoEvent};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EdgeKey {
    pub peer: String,
    pub transport: String,
    pub port: u16,
    pub outbound: bool,
}

impl EdgeKey {
    pub fn of(f: &Flow) -> EdgeKey {
        EdgeKey { peer: f.peer_ip.clone(), transport: f.transport.clone(), port: f.port, outbound: f.outbound }
    }
    pub fn label(&self) -> String {
        format!("{} {}:{}/{}", if self.outbound { "to" } else { "from" }, self.peer, self.port, self.transport)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeStats {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_op: Option<OpClass>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Exponentially weighted bytes per observation.
    pub avg_bytes: f64,
    pub samples: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Learning,
    Monitoring,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearningPolicy {
    /// Minimum learning duration.
    pub min_hours: i64,
    /// Maximum learning duration (ends regardless).
    pub max_hours: i64,
    /// Learning ends early when fewer new edges than this were added in
    /// the last `quiet_hours`.
    pub new_edge_threshold: u32,
    pub quiet_hours: i64,
}

impl Default for LearningPolicy {
    fn default() -> Self {
        LearningPolicy { min_hours: 24, max_hours: 24 * 21, new_edge_threshold: 1, quiet_hours: 24 }
    }
}

/// The learned behaviour of one device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub network_mode: Mode,
    /// Process-value learning runs independently (AE-IOT-0009).
    pub process_mode: Mode,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    pub edges: BTreeMap<String, (EdgeKey, EdgeStats)>,
    /// Process variables: "protocol:object" -> (min, max).
    pub values: BTreeMap<String, (i64, i64)>,
    /// Times new edges were added (bounded ring) for completion detection.
    pub additions: Vec<DateTime<Utc>>,
    /// Operations seen per protocol ("modbus:read_holding_registers").
    pub operations: BTreeSet<String>,
    pub version: u64,
}

const MAX_EDGES: usize = 2048;
const MAX_VALUES: usize = 512;

fn ek(k: &EdgeKey) -> String {
    format!("{}|{}|{}|{}", k.peer, k.transport, k.port, if k.outbound { "o" } else { "i" })
}

impl Baseline {
    pub fn new(at: DateTime<Utc>) -> Baseline {
        Baseline {
            network_mode: Mode::Learning,
            process_mode: Mode::Learning,
            started_at: at,
            completed_at: None,
            edges: BTreeMap::new(),
            values: BTreeMap::new(),
            additions: vec![],
            operations: BTreeSet::new(),
            version: 0,
        }
    }

    pub fn has_edge(&self, k: &EdgeKey) -> bool {
        self.edges.contains_key(&ek(k))
    }

    /// Absorb an edge (learning, or an anomaly acknowledged as learned).
    pub fn learn_edge(&mut self, f: &Flow, at: DateTime<Utc>) {
        let k = EdgeKey::of(f);
        let key = ek(&k);
        let n = self.edges.len();
        match self.edges.get_mut(&key) {
            Some((_, s)) => {
                s.last_seen = at;
                s.samples += 1;
                s.avg_bytes = s.avg_bytes * 0.8 + f.bytes as f64 * 0.2;
                if f.max_op > s.max_op {
                    s.max_op = f.max_op;
                }
            }
            None if n < MAX_EDGES => {
                self.edges.insert(
                    key,
                    (k, EdgeStats { protocol: f.protocol.map(|p| p.as_str().to_string()), max_op: f.max_op, first_seen: at, last_seen: at, avg_bytes: f.bytes as f64, samples: 1 }),
                );
                self.additions.push(at);
                if self.additions.len() > 256 {
                    self.additions.remove(0);
                }
                self.version += 1;
            }
            None => {}
        }
        for o in &f.operations {
            if self.operations.len() < 512 {
                self.operations.insert(o.clone());
            }
        }
    }

    pub fn learn_value(&mut self, key: &str, v: i64) {
        if let Some((lo, hi)) = self.values.get_mut(key) {
            *lo = (*lo).min(v);
            *hi = (*hi).max(v);
        } else if self.values.len() < MAX_VALUES {
            self.values.insert(key.to_string(), (v, v));
        }
    }

    /// Move to monitoring when the learning policy says so.
    pub fn maybe_complete(&mut self, now: DateTime<Utc>, p: &LearningPolicy) -> bool {
        if self.network_mode != Mode::Learning {
            return false;
        }
        let age = now - self.started_at;
        let recent = self.additions.iter().filter(|t| **t > now - Duration::hours(p.quiet_hours)).count() as u32;
        if age >= Duration::hours(p.max_hours) || (age >= Duration::hours(p.min_hours) && recent < p.new_edge_threshold) {
            self.network_mode = Mode::Monitoring;
            self.process_mode = Mode::Monitoring;
            self.completed_at = Some(now);
            self.version += 1;
            return true;
        }
        false
    }

    /// Allow-list rules derived from the baseline (outbound edges with
    /// their maximum operation class) — input to policy recommendations.
    pub fn allow_list(&self) -> Vec<(EdgeKey, Option<String>, Option<OpClass>)> {
        self.edges.values().filter(|(k, _)| k.outbound).map(|(k, s)| (k.clone(), s.protocol.clone(), s.max_op)).collect()
    }

    /// Differences between this baseline and an earlier snapshot.
    pub fn diff(&self, earlier: &Baseline) -> (Vec<EdgeKey>, Vec<EdgeKey>) {
        let added = self.edges.iter().filter(|(k, _)| !earlier.edges.contains_key(*k)).map(|(_, v)| v.0.clone()).collect();
        let removed = earlier.edges.iter().filter(|(k, _)| !self.edges.contains_key(*k)).map(|(_, v)| v.0.clone()).collect();
        (added, removed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    NewCommunication,
    NewProtocol,
    NewOperation,
    EngineeringOperation,
    ControllerModeChange,
    FirmwareOperation,
    UnauthorizedEngineeringStation,
    ProcessValueOutOfRange,
    VolumeSpike,
    ScanDetected,
    MalformedProtocol,
    ProtocolErrors,
    InternetCommunication,
    ThreatIntelMatch,
}

pub const ANOMALY_KINDS: &[&str] = &[
    "new_communication",
    "new_protocol",
    "new_operation",
    "engineering_operation",
    "controller_mode_change",
    "firmware_operation",
    "unauthorized_engineering_station",
    "process_value_out_of_range",
    "volume_spike",
    "scan_detected",
    "malformed_protocol",
    "protocol_errors",
    "internet_communication",
    "threat_intel_match",
];

impl AnomalyKind {
    pub fn as_str(&self) -> &'static str {
        ANOMALY_KINDS[*self as usize]
    }
    /// Fires during learning too (signature-like, not deviation-based).
    pub fn always(&self) -> bool {
        matches!(
            self,
            AnomalyKind::EngineeringOperation
                | AnomalyKind::ControllerModeChange
                | AnomalyKind::FirmwareOperation
                | AnomalyKind::UnauthorizedEngineeringStation
                | AnomalyKind::ScanDetected
                | AnomalyKind::MalformedProtocol
                | AnomalyKind::ThreatIntelMatch
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    /// 0..10.
    pub severity: f64,
    pub title: String,
    /// Dedup key per device.
    pub key: String,
    pub evidence: serde_json::Value,
}

/// Context for detection on one device.
#[derive(Debug, Clone, Default)]
pub struct DetectContext<'a> {
    /// The device is an engineering workstation (by classification or designation).
    pub engineering_station: bool,
    /// The device is designated as a scanner (no scan anomalies).
    pub scanner: bool,
    /// The device is safety-sensitive (raises severities).
    pub safety_sensitive: bool,
    /// Peer IPs of designated engineering stations.
    pub engineering_peers: &'a [String],
    /// Known malicious indicators (IP addresses or domains).
    pub threat_indicators: Option<&'a BTreeSet<String>>,
    /// Malformed protocol messages counted for the device in the window.
    pub malformed: u64,
    pub protocol_errors: u64,
}

fn sev(base: f64, safety: bool) -> f64 {
    (if safety { base + 1.5 } else { base }).min(10.0)
}

/// Detect anomalies in a device's new flows and protocol events, updating
/// the baseline while learning.
pub fn detect(b: &mut Baseline, flows: &[Flow], events: &[(ProtoEvent, bool)], ctx: &DetectContext<'_>, now: DateTime<Utc>) -> Vec<Anomaly> {
    let mut out: Vec<Anomaly> = vec![];
    let learning = b.network_mode == Mode::Learning;
    fn push_to(out: &mut Vec<Anomaly>, learning: bool, a: Anomaly) {
        if (!learning || a.kind.always()) && !out.iter().any(|x| x.key == a.key) {
            out.push(a);
        }
    }
    macro_rules! push {
        ($a:expr) => {
            push_to(&mut out, learning, $a)
        };
    }
    // Scans: many distinct peers or ports initiated in one batch.
    let peers: BTreeSet<&str> = flows.iter().filter(|f| f.outbound).map(|f| f.peer_ip.as_str()).collect();
    let ports: BTreeSet<u16> = flows.iter().filter(|f| f.outbound).map(|f| f.port).collect();
    if !ctx.scanner && (peers.len() >= 32 || ports.len() >= 32) {
        push!(Anomaly {
            kind: AnomalyKind::ScanDetected,
            severity: sev(7.0, false),
            title: format!("scanning activity: {} peers, {} ports", peers.len(), ports.len()),
            key: "scan".into(),
            evidence: serde_json::json!({ "peers": peers.len(), "ports": ports.len() }),
        });
    }
    for f in flows {
        if let Ok(ip) = f.peer_ip.parse::<std::net::IpAddr>() {
            if ctx.threat_indicators.map(|t| t.contains(&f.peer_ip)).unwrap_or(false) {
                push!(Anomaly {
                    kind: AnomalyKind::ThreatIntelMatch,
                    severity: 9.0,
                    title: format!("communication with known malicious address {}", f.peer_ip),
                    key: format!("ti:{}", f.peer_ip),
                    evidence: serde_json::json!({ "indicator": f.peer_ip, "port": f.port }),
                });
            }
            let k = EdgeKey::of(f);
            if !b.has_edge(&k) && crate::risk::is_public(&ip) && f.outbound {
                push!(Anomaly {
                    kind: AnomalyKind::InternetCommunication,
                    severity: sev(5.0, ctx.safety_sensitive),
                    title: format!("new internet destination {}:{}", f.peer_ip, f.port),
                    key: format!("inet:{}:{}", f.peer_ip, f.port),
                    evidence: serde_json::json!({ "edge": k }),
                });
            }
        }
        let k = EdgeKey::of(f);
        match b.edges.get(&ek(&k)) {
            None => {
                let new_proto = f.protocol.map(|p| !b.edges.values().any(|(_, s)| s.protocol.as_deref() == Some(p.as_str()))).unwrap_or(false);
                if new_proto {
                    push!(Anomaly {
                        kind: AnomalyKind::NewProtocol,
                        severity: sev(6.0, ctx.safety_sensitive),
                        title: format!("first use of {} ({})", f.protocol.map(|p| p.as_str()).unwrap_or("?"), k.label()),
                        key: format!("proto:{}", f.protocol.map(|p| p.as_str()).unwrap_or("?")),
                        evidence: serde_json::json!({ "edge": k, "operations": f.operations }),
                    });
                }
                push!(Anomaly {
                    kind: AnomalyKind::NewCommunication,
                    severity: sev(if f.max_op.map(|o| o.is_modifying()).unwrap_or(false) { 6.5 } else { 4.0 }, ctx.safety_sensitive),
                    title: format!("new communication {}", k.label()),
                    key: format!("edge:{}", ek(&k)),
                    evidence: serde_json::json!({ "edge": k, "protocol": f.protocol, "max_op": f.max_op, "bytes": f.bytes }),
                });
            }
            Some((_, s)) => {
                if let (Some(now_op), base) = (f.max_op, s.max_op) {
                    if base.map(|b0| now_op > b0).unwrap_or(true) && now_op.is_modifying() {
                        push!(Anomaly {
                            kind: AnomalyKind::NewOperation,
                            severity: sev(6.5, ctx.safety_sensitive),
                            title: format!("{} operations on an edge that only saw {}", now_op.as_str(), base.map(|b0| b0.as_str()).unwrap_or("none")),
                            key: format!("op:{}:{}", ek(&k), now_op.as_str()),
                            evidence: serde_json::json!({ "edge": k, "baseline_max_op": base, "observed_max_op": now_op }),
                        });
                    }
                }
                if s.samples >= 5 && f.bytes as f64 > s.avg_bytes * 10.0 && f.bytes > 100_000 {
                    push!(Anomaly {
                        kind: AnomalyKind::VolumeSpike,
                        severity: sev(5.0, ctx.safety_sensitive),
                        title: format!("traffic volume {}x the baseline {}", (f.bytes as f64 / s.avg_bytes.max(1.0)).round(), k.label()),
                        key: format!("vol:{}", ek(&k)),
                        evidence: serde_json::json!({ "edge": k, "bytes": f.bytes, "baseline_avg_bytes": s.avg_bytes.round() }),
                    });
                }
            }
        }
        if learning {
            b.learn_edge(f, now);
        } else if let Some((_, s)) = b.edges.get_mut(&ek(&k)) {
            // Known edges keep their statistics current while monitoring.
            s.last_seen = now;
            s.samples += 1;
            s.avg_bytes = s.avg_bytes * 0.8 + f.bytes as f64 * 0.2;
        }
    }
    for (e, server) in events {
        if e.is_response {
            continue;
        }
        let as_client = !*server;
        match e.class {
            OpClass::Program if as_client => {
                if !ctx.engineering_station {
                    push!(Anomaly {
                        kind: AnomalyKind::UnauthorizedEngineeringStation,
                        severity: 9.0,
                        title: format!("{} {} issued by a device that is not an engineering workstation", e.protocol.as_str(), e.operation),
                        key: format!("ues:{}:{}", e.protocol.as_str(), e.operation),
                        evidence: serde_json::json!({ "protocol": e.protocol, "operation": e.operation }),
                    });
                }
                push!(Anomaly {
                    kind: AnomalyKind::EngineeringOperation,
                    severity: 6.0,
                    title: format!("engineering operation {} {}", e.protocol.as_str(), e.operation),
                    key: format!("eng:{}:{}", e.protocol.as_str(), e.operation),
                    evidence: serde_json::json!({ "protocol": e.protocol, "operation": e.operation, "object": e.object }),
                });
            }
            OpClass::Firmware if as_client => push!(Anomaly {
                kind: AnomalyKind::FirmwareOperation,
                severity: 8.0,
                title: format!("firmware operation {} {}", e.protocol.as_str(), e.operation),
                key: format!("fw:{}:{}", e.protocol.as_str(), e.operation),
                evidence: serde_json::json!({ "protocol": e.protocol, "operation": e.operation }),
            }),
            OpClass::Control if as_client && is_mode_change(&e.operation) => push!(Anomaly {
                kind: AnomalyKind::ControllerModeChange,
                severity: 8.5,
                title: format!("controller mode change: {} {}", e.protocol.as_str(), e.operation),
                key: format!("mode:{}:{}", e.protocol.as_str(), e.operation),
                evidence: serde_json::json!({ "protocol": e.protocol, "operation": e.operation, "details": e.details }),
            }),
            _ => {}
        }
        // Process values (writes): learn ranges, then flag excursions.
        if e.class == OpClass::Write && !e.values.is_empty() {
            let key = format!("{}:{}", e.protocol.as_str(), e.object.as_deref().unwrap_or("?"));
            if b.process_mode == Mode::Learning {
                for v in &e.values {
                    b.learn_value(&key, *v);
                }
            } else if let Some((lo, hi)) = b.values.get(&key).copied() {
                let span = (hi - lo).max(1);
                if let Some(v) = e.values.iter().find(|v| **v < lo - span / 5 || **v > hi + span / 5) {
                    let a = Anomaly {
                        kind: AnomalyKind::ProcessValueOutOfRange,
                        severity: sev(7.0, ctx.safety_sensitive),
                        title: format!("value {v} written to {key} outside the learned range {lo}..{hi}"),
                        key: format!("pv:{key}"),
                        evidence: serde_json::json!({ "object": key, "value": v, "learned_min": lo, "learned_max": hi }),
                    };
                    if !out.iter().any(|x| x.key == a.key) {
                        out.push(a);
                    }
                }
            }
        }
    }
    if ctx.malformed >= 10 {
        push!(Anomaly {
            kind: AnomalyKind::MalformedProtocol,
            severity: sev(6.0, ctx.safety_sensitive),
            title: format!("{} malformed industrial protocol messages", ctx.malformed),
            key: "malformed".into(),
            evidence: serde_json::json!({ "count": ctx.malformed }),
        });
    }
    if ctx.protocol_errors >= 20 && !learning {
        push!(Anomaly {
            kind: AnomalyKind::ProtocolErrors,
            severity: sev(4.5, ctx.safety_sensitive),
            title: format!("{} protocol exception responses", ctx.protocol_errors),
            key: "proto_errors".into(),
            evidence: serde_json::json!({ "count": ctx.protocol_errors }),
        });
    }
    let _ = ctx.engineering_peers;
    out.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap_or(std::cmp::Ordering::Equal).then(a.key.cmp(&b.key)));
    out
}

fn is_mode_change(op: &str) -> bool {
    matches!(
        op,
        "plc_stop"
            | "plc_control"
            | "stop"
            | "start"
            | "reset"
            | "cold_restart"
            | "warm_restart"
            | "stop_application"
            | "start_application"
            | "diagnostics_restart_communications"
            | "diagnostics_force_listen_only"
            | "reinitialize_device"
            | "device_communication_control"
            | "reset_process"
            | "factory_reset"
            | "rpc_control"
            | "stopdt_act"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::Protocol;

    fn flow(peer: &str, port: u16, op: Option<OpClass>, bytes: u64) -> Flow {
        Flow {
            peer_ip: peer.into(),
            peer_mac: None,
            transport: "tcp".into(),
            port,
            outbound: false,
            packets: 1,
            bytes,
            protocol: Some(Protocol::Modbus),
            max_op: op,
            operations: vec![],
        }
    }

    #[test]
    fn learning_then_drift() {
        let t0 = Utc::now() - Duration::days(3);
        let mut b = Baseline::new(t0);
        let ctx = DetectContext::default();
        let a = detect(&mut b, &[flow("10.0.0.9", 502, Some(OpClass::Read), 500)], &[], &ctx, t0);
        assert!(a.is_empty(), "no deviation anomalies while learning");
        assert!(b.maybe_complete(t0 + Duration::hours(30), &LearningPolicy::default()));
        assert_eq!(b.network_mode, Mode::Monitoring);
        let now = t0 + Duration::hours(31);
        let a = detect(&mut b, &[flow("10.0.0.9", 502, Some(OpClass::Read), 500)], &[], &ctx, now);
        assert!(a.is_empty());
        let a = detect(&mut b, &[flow("10.0.0.9", 502, Some(OpClass::Write), 500)], &[], &ctx, now);
        assert_eq!(a[0].kind, AnomalyKind::NewOperation);
        let a = detect(&mut b, &[flow("10.0.0.66", 502, Some(OpClass::Write), 500)], &[], &DetectContext { safety_sensitive: true, ..Default::default() }, now);
        assert!(a.iter().any(|x| x.kind == AnomalyKind::NewCommunication && x.severity > 6.5));
        // Acknowledged as learned: absorbed and no longer reported.
        b.learn_edge(&flow("10.0.0.66", 502, Some(OpClass::Write), 500), now);
        assert!(detect(&mut b, &[flow("10.0.0.66", 502, Some(OpClass::Write), 500)], &[], &ctx, now).is_empty());
        let snap = b.clone();
        b.learn_edge(&flow("10.0.0.70", 502, None, 1), now);
        let (added, removed) = b.diff(&snap);
        assert_eq!((added.len(), removed.len()), (1, 0));
    }

    #[test]
    fn signatures_fire_while_learning() {
        let mut b = Baseline::new(Utc::now());
        let stop = ProtoEvent::new(Protocol::S7comm, "plc_stop", 0x29, OpClass::Control);
        let dl = ProtoEvent::new(Protocol::S7comm, "download_block", 0x1b, OpClass::Program);
        let a = detect(&mut b, &[], &[(stop, false), (dl.clone(), false)], &DetectContext::default(), Utc::now());
        let kinds: Vec<AnomalyKind> = a.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&AnomalyKind::ControllerModeChange));
        assert!(kinds.contains(&AnomalyKind::UnauthorizedEngineeringStation));
        let ok = detect(&mut b, &[], &[(dl, false)], &DetectContext { engineering_station: true, ..Default::default() }, Utc::now());
        assert!(ok.iter().all(|x| x.kind != AnomalyKind::UnauthorizedEngineeringStation));
        // Scanner designation.
        let many: Vec<Flow> = (0..40).map(|i| Flow { outbound: true, ..flow(&format!("10.1.0.{i}"), 80, None, 60) }).collect();
        assert!(detect(&mut b, &many, &[], &DetectContext::default(), Utc::now()).iter().any(|x| x.kind == AnomalyKind::ScanDetected));
        assert!(!detect(&mut b, &many, &[], &DetectContext { scanner: true, ..Default::default() }, Utc::now()).iter().any(|x| x.kind == AnomalyKind::ScanDetected));
    }

    #[test]
    fn process_values_and_threat_intel() {
        let t0 = Utc::now();
        let mut b = Baseline::new(t0);
        let mut w = ProtoEvent::new(Protocol::Modbus, "write_single_register", 6, OpClass::Write);
        w.object = Some("register:10".into());
        for v in [100, 120, 140] {
            let mut e = w.clone();
            e.values = vec![v];
            detect(&mut b, &[], &[(e, false)], &DetectContext::default(), t0);
        }
        assert_eq!(b.values.get("modbus:register:10"), Some(&(100, 140)));
        b.process_mode = Mode::Monitoring;
        b.network_mode = Mode::Monitoring;
        let mut hi = w.clone();
        hi.values = vec![900];
        let a = detect(&mut b, &[], &[(hi, false)], &DetectContext::default(), t0);
        assert_eq!(a[0].kind, AnomalyKind::ProcessValueOutOfRange);
        let mut ok = w.clone();
        ok.values = vec![130];
        assert!(detect(&mut b, &[], &[(ok, false)], &DetectContext::default(), t0).is_empty());
        let ti: BTreeSet<String> = ["203.0.113.66".to_string()].into_iter().collect();
        let f = Flow { outbound: true, ..flow("203.0.113.66", 443, None, 100) };
        let a = detect(&mut b, &[f], &[], &DetectContext { threat_indicators: Some(&ti), ..Default::default() }, t0);
        assert!(a.iter().any(|x| x.kind == AnomalyKind::ThreatIntelMatch));
    }

    #[test]
    fn automatic_learning_completion() {
        let t0 = Utc::now() - Duration::days(30);
        let p = LearningPolicy { min_hours: 24, max_hours: 24 * 21, new_edge_threshold: 1, quiet_hours: 24 };
        let mut b = Baseline::new(t0);
        b.learn_edge(&flow("10.0.0.1", 502, None, 1), t0 + Duration::hours(20));
        assert!(!b.maybe_complete(t0 + Duration::hours(22), &p), "minimum duration not reached");
        assert!(b.maybe_complete(t0 + Duration::hours(50), &p), "quiet for a day");
        let mut busy = Baseline::new(t0);
        let ok = busy.maybe_complete(t0 + Duration::hours(24 * 22), &p);
        assert!(ok, "maximum duration ends learning");
    }
}
