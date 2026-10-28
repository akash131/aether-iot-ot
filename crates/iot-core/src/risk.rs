//! Device risk model (ZTE-IOT sections 58 Device Risk Model, 59 Exposure
//! Risk, 60 Behavior Risk, 61 Protocol Risk, 62 Identity Confidence Risk,
//! 67 Threat Intelligence Correlation, 68 Malware/C2 Correlation, 69 Risk
//! Prioritization; Volume 2 "Risk Profiling"; AE-IOT-0017 tunable risk
//! factors, AE-IOT-0018 operational impact score).
//!
//! The score is explainable: each factor has a score (0–100), a weight and
//! a reason; factors combine with a weighted noisy-OR so independent
//! problems compound without exceeding 100. Tenants may re-weight or
//! disable factor types. A separate **impact** score expresses the
//! consequence of compromise (business criticality and safety), and the
//! **priority** used for remediation queues combines both. Risk never
//! blocks traffic by itself (ZTE-IOTINV-153168): enforcement requires an
//! explicitly approved policy that references risk.

use crate::taxonomy;
use crate::vuln::{Finding, FindingKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

pub const RISK_MODEL_VERSION: &str = "2026.10.1";

pub const FACTORS: &[(&str, &str, f64)] = &[
    ("vulnerability", "Known vulnerabilities", 1.0),
    ("end_of_life", "End-of-life hardware or firmware", 0.6),
    ("exposure", "Network exposure (internet, management services)", 0.9),
    ("credentials", "Cleartext or default credentials", 0.9),
    ("protocol", "Insecure or high-impact protocol use", 0.6),
    ("behavior", "Anomalous behaviour", 0.8),
    ("identity", "Low identification confidence", 0.4),
    ("threat_intel", "Contact with known malicious infrastructure", 1.0),
];

/// Public (internet-routable) address.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_unspecified()
                || v.is_multicast()
                || v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64
                || v.octets()[0] >= 240)
        }
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// Tenant tuning: weight per factor (0 disables).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tuning {
    #[serde(default)]
    pub weights: BTreeMap<String, f64>,
}

impl Tuning {
    pub fn weight(&self, factor: &str) -> f64 {
        self.weights.get(factor).copied().unwrap_or_else(|| FACTORS.iter().find(|f| f.0 == factor).map(|f| f.2).unwrap_or(0.0)).clamp(0.0, 2.0)
    }
    pub fn validate(&self) -> Result<(), String> {
        for (k, v) in &self.weights {
            if !FACTORS.iter().any(|f| f.0 == k) {
                return Err(format!("unknown risk factor {k}"));
            }
            if !(0.0..=2.0).contains(v) {
                return Err(format!("weight of {k} must be 0..2"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct RiskInput {
    pub device_type: String,
    pub classification_confidence: f64,
    pub randomized_mac: bool,
    /// Business criticality override (1..5).
    pub criticality: Option<u8>,
    pub findings: Vec<Finding>,
    pub open_anomalies: u32,
    /// Highest open anomaly severity (0..10).
    pub anomaly_severity: f64,
    pub internet_inbound: bool,
    pub internet_outbound_peers: u32,
    /// Peers issuing modifying (write/control/program) operations to the device.
    pub modifying_peers: u32,
    /// The device itself issued program/firmware operations.
    pub issues_engineering_ops: bool,
    pub threat_hits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskFactor {
    pub key: String,
    pub label: String,
    pub score: f64,
    pub weight: f64,
    pub contribution: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u8,
    pub level: String,
    /// Consequence of compromise, 0..100.
    pub impact: u8,
    /// Remediation priority, 0..100.
    pub priority: u8,
    pub factors: Vec<RiskFactor>,
    pub model_version: String,
}

pub fn level(score: u8) -> &'static str {
    match score {
        85..=100 => "critical",
        70..=84 => "high",
        40..=69 => "medium",
        _ => "low",
    }
}

pub fn score(input: &RiskInput, tuning: &Tuning) -> RiskScore {
    let info = taxonomy::get(&input.device_type);
    let mut raw: Vec<(&str, f64, Vec<String>)> = vec![];
    let by = |k: FindingKind| input.findings.iter().filter(move |f| f.kind == k);
    // Vulnerabilities: highest CVSS, raised for exploited ones and counts.
    let vulns: Vec<&Finding> = by(FindingKind::Vulnerability).collect();
    if let Some(max) = vulns.iter().map(|f| f.severity).fold(None, |a: Option<f64>, b| Some(a.map_or(b, |x| x.max(b)))) {
        let kev = vulns.iter().any(|f| f.known_exploited);
        let s = (max * 9.0 + if kev { 15.0 } else { 0.0 } + (vulns.len() as f64 - 1.0).max(0.0) * 2.0).min(100.0);
        raw.push(("vulnerability", s, vec![format!("{} applicable advisories, highest CVSS {max:.1}{}", vulns.len(), if kev { ", known exploited" } else { "" })]));
    }
    if let Some(e) = by(FindingKind::EndOfLife).next() {
        raw.push(("end_of_life", e.severity * 10.0, vec![e.title.clone()]));
    }
    let mut exp = 0.0f64;
    let mut exp_r = vec![];
    if input.internet_inbound {
        exp = exp.max(90.0);
        exp_r.push("reachable from the internet".to_string());
    }
    if input.internet_outbound_peers > 0 {
        let s = if taxonomy::is_ot(info.category) { 60.0 } else { 25.0 } + (input.internet_outbound_peers as f64).min(10.0) * 2.0;
        exp = exp.max(s);
        exp_r.push(format!("communicates with {} internet destinations", input.internet_outbound_peers));
    }
    if exp > 0.0 {
        raw.push(("exposure", exp, exp_r));
    }
    let creds: Vec<&Finding> = input.findings.iter().filter(|f| matches!(f.kind, FindingKind::CleartextCredentials | FindingKind::DefaultCredentials)).collect();
    if !creds.is_empty() {
        let max = creds.iter().map(|f| f.severity).fold(0.0, f64::max);
        raw.push(("credentials", max * 10.0, creds.iter().map(|f| f.title.clone()).collect()));
    }
    let insecure: Vec<&Finding> = by(FindingKind::InsecureProtocol).collect();
    let mut proto = insecure.iter().map(|f| f.severity * 8.0).fold(0.0, f64::max);
    let mut proto_r: Vec<String> = insecure.iter().map(|f| f.title.clone()).collect();
    if input.modifying_peers > 2 && info.safety_sensitive {
        proto = proto.max(55.0 + (input.modifying_peers as f64).min(10.0) * 3.0);
        proto_r.push(format!("{} peers issue write/control operations to a safety-sensitive device", input.modifying_peers));
    }
    if input.issues_engineering_ops && info.key != "engineering_workstation" {
        proto = proto.max(70.0);
        proto_r.push("issues program or firmware operations but is not an engineering workstation".into());
    }
    if proto > 0.0 {
        raw.push(("protocol", proto, proto_r));
    }
    if input.open_anomalies > 0 {
        raw.push(("behavior", (input.anomaly_severity * 8.0 + input.open_anomalies.min(10) as f64 * 2.0).min(100.0), vec![format!("{} open anomalies", input.open_anomalies)]));
    }
    let mut id_s = 0.0;
    let mut id_r = vec![];
    if input.classification_confidence < 0.7 {
        id_s = (0.7 - input.classification_confidence) / 0.7 * 60.0;
        id_r.push(format!("classification confidence {:.2}", input.classification_confidence));
    }
    if input.randomized_mac {
        id_s += 15.0;
        id_r.push("randomised MAC address".into());
    }
    if id_s > 0.0 {
        raw.push(("identity", id_s.min(100.0), id_r));
    }
    if !input.threat_hits.is_empty() {
        raw.push(("threat_intel", 95.0, input.threat_hits.iter().take(5).map(|t| format!("contacted {t}")).collect()));
    }
    let mut factors = vec![];
    let mut keep = 1.0;
    for (k, s, reasons) in raw {
        let w = tuning.weight(k);
        let label = FACTORS.iter().find(|f| f.0 == k).map(|f| f.1).unwrap_or(k);
        let c = (s / 100.0 * w).clamp(0.0, 1.0);
        keep *= 1.0 - c;
        factors.push(RiskFactor { key: k.into(), label: label.into(), score: s.round(), weight: w, contribution: (c * 100.0).round(), reasons });
    }
    factors.sort_by(|a, b| b.contribution.partial_cmp(&a.contribution).unwrap_or(std::cmp::Ordering::Equal).then(a.key.cmp(&b.key)));
    let score = ((1.0 - keep) * 100.0).round().clamp(0.0, 100.0) as u8;
    let crit = input.criticality.unwrap_or(info.criticality).clamp(1, 5) as f64;
    let impact = ((crit / 5.0) * 80.0 + if info.safety_sensitive { 20.0 } else { 0.0 }).round().min(100.0) as u8;
    let priority = ((score as f64) * (0.5 + impact as f64 / 200.0)).round().min(100.0) as u8;
    RiskScore { score, level: level(score).into(), impact, priority, factors, model_version: RISK_MODEL_VERSION.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: FindingKind, sev: f64, kev: bool) -> Finding {
        Finding {
            kind,
            key: format!("{}:{sev}", kind.as_str()),
            title: kind.as_str().into(),
            severity: sev,
            known_exploited: kev,
            detail: serde_json::json!({}),
            remediation: None,
        }
    }

    #[test]
    fn scores_compound_and_explain() {
        let clean = score(&RiskInput { device_type: "plc".into(), classification_confidence: 0.95, ..Default::default() }, &Tuning::default());
        assert_eq!((clean.score, clean.level.as_str()), (0, "low"));
        assert!(clean.impact >= 90, "PLC impact is high: {}", clean.impact);
        let vuln = RiskInput { device_type: "plc".into(), classification_confidence: 0.95, findings: vec![finding(FindingKind::Vulnerability, 9.8, true)], ..Default::default() };
        let v = score(&vuln, &Tuning::default());
        assert!(v.score >= 85, "{v:?}");
        let mut more = vuln.clone();
        more.internet_inbound = true;
        more.findings.push(finding(FindingKind::CleartextCredentials, 6.5, false));
        let m = score(&more, &Tuning::default());
        assert!(m.score >= v.score);
        assert_eq!(m.factors[0].key, "vulnerability");
        assert!(m.factors.iter().all(|f| !f.reasons.is_empty()));
        // Tuning: disabling a factor removes its contribution.
        let t = Tuning { weights: [("vulnerability".to_string(), 0.0)].into_iter().collect() };
        assert!(t.validate().is_ok());
        let tuned = score(&vuln, &t);
        assert_eq!(tuned.score, 0);
        assert!(Tuning { weights: [("bogus".to_string(), 1.0)].into_iter().collect() }.validate().is_err());
        // Identity confidence risk.
        let unknown = score(&RiskInput { device_type: "unknown".into(), classification_confidence: 0.1, randomized_mac: true, ..Default::default() }, &Tuning::default());
        assert!(unknown.factors.iter().any(|f| f.key == "identity"));
        // Low criticality device with the same vulnerability has lower priority.
        let cam = score(&RiskInput { device_type: "smart_tv".into(), ..vuln.clone() }, &Tuning::default());
        assert!(cam.priority < v.priority);
    }

    #[test]
    fn public_addresses() {
        assert!(is_public(&"8.8.8.8".parse().unwrap()));
        assert!(!is_public(&"10.1.2.3".parse().unwrap()));
        assert!(!is_public(&"100.64.0.1".parse().unwrap()));
        assert!(!is_public(&"fe80::1".parse().unwrap()));
        assert!(is_public(&"2001:4860::8888".parse().unwrap()));
    }
}
