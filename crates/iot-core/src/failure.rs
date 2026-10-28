//! Safety / failure matrix (the "Safety / Failure Matrix" subsection of
//! every ZTE-IOT capability; ZTE-IOT-*-i7 safe behaviour for sensor loss,
//! stale inventory, uncertain classification, policy distribution failure
//! and branch/cloud outage; ZTE-IOTINV-153167 loss of cloud connectivity
//! never collapses segmentation).
//!
//! Every failure mode declares how it is **detected**, its **safety** and
//! **security** impact, the **fallback** behaviour of the product, how it
//! **recovers**, the **alert** raised and the **operator action**.
//! [`evaluate`] turns measured health into the list of active failure
//! modes with that guidance; the control plane and the edge both expose it
//! (status endpoints, heartbeats, alerts).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Mode {
    pub key: &'static str,
    pub label: &'static str,
    pub detection: &'static str,
    pub safety_impact: &'static str,
    pub security_impact: &'static str,
    pub fallback: &'static str,
    pub recovery: &'static str,
    pub alert: &'static str,
    /// 0..10.
    pub severity: u8,
    pub operator_action: &'static str,
}

macro_rules! m {
    ($k:expr, $l:expr, $d:expr, $s:expr, $sec:expr, $f:expr, $r:expr, $a:expr, $sev:expr, $o:expr) => {
        Mode { key: $k, label: $l, detection: $d, safety_impact: $s, security_impact: $sec, fallback: $f, recovery: $r, alert: $a, severity: $sev, operator_action: $o }
    };
}

pub const MODES: &[Mode] = &[
    m!(
        "sensor_loss",
        "Sensor loss",
        "no heartbeat or observations from a sensor for longer than the sensor timeout",
        "none: collection is passive; enforcement continues on the last policy",
        "visibility gap: new devices and anomalies on the site are not seen",
        "inventory entries keep their last state and are marked stale after the inactivity window; enforcement nodes keep enforcing the last verified policy",
        "the sensor re-enrols or reconnects and resumes; observations resume from the live traffic (no replay required)",
        "iot.sensor_offline",
        6,
        "check the sensor host, its mirror/tap and its platform connectivity"
    ),
    m!(
        "packet_loss",
        "Packet loss at capture",
        "capture drop counters (kernel, ring, queue) exceed the drop-ratio threshold",
        "none",
        "missed protocol operations and flows; classification confidence may be lower",
        "observations are still produced from what was captured; drops are reported with the observation batches",
        "drops stop when load falls or capacity is added",
        "iot.capture_drops",
        4,
        "reduce mirrored traffic (filters), add capture capacity or move to a dedicated tap"
    ),
    m!(
        "duplicate_observations",
        "Duplicate observations",
        "the same device is reported by several sensors or replayed batches (batch id replay, multi-sensor rate)",
        "none",
        "inflated counts; risk of duplicate assets",
        "identity resolution consolidates by MAC/serial; replayed batches are idempotent by batch id",
        "automatic",
        "iot.duplicate_observations",
        2,
        "review overlapping mirror sources if the rate stays high"
    ),
    m!(
        "ip_change",
        "IP address change",
        "a known device (by MAC or serial) appears with a new IP address",
        "none: identity is not bound to the IP address",
        "address-based rules on other systems may follow the old address",
        "the asset keeps its identity; the new address is recorded with an asset change event; enforcement uses the device identity and refreshed address sets",
        "address sets refresh on the next edge configuration sync",
        "iot.asset_ip_changed",
        2,
        "none unless the change is unexpected for a fixed-address OT device"
    ),
    m!(
        "mac_randomization",
        "MAC randomisation",
        "locally administered MAC addresses on new devices",
        "none",
        "devices may appear as new; vendor evidence from the OUI is unavailable",
        "identity falls back to DHCP client identifier, host name and serial; the vendor is not inferred from randomised MACs",
        "automatic once a stronger key is observed",
        "iot.mac_randomized",
        2,
        "disable MAC randomisation on managed networks where possible"
    ),
    m!(
        "classification_ambiguity",
        "Classification ambiguity",
        "conflicting evidence or confidence below the privileged threshold",
        "none: uncertain devices never receive privileged segments",
        "least privilege: the device is held in the observation group",
        "the device is placed in the unclassified (observe) group or quarantine when unknown; conflicts are listed for review",
        "more evidence, a tenant rule or an administrator override resolves it",
        "iot.classification_ambiguous",
        3,
        "review the evidence and confirm or override the classification"
    ),
    m!(
        "parser_crash",
        "Parser failure",
        "a protocol parser error or panic is caught (per protocol counters)",
        "none: parsing is passive and isolated per payload",
        "operations of that protocol may be missed",
        "the payload is skipped, counted and the parser stays available; other protocols continue",
        "automatic; parser errors are reported with stable codes",
        "iot.parser_failure",
        5,
        "report the sample (evidence-minimised counters) and upgrade the edge when a fix is available"
    ),
    m!(
        "malformed_industrial_packet",
        "Malformed industrial packet",
        "malformed messages per protocol and device above the threshold",
        "possible: malformed traffic can crash fragile devices",
        "possible fuzzing or exploitation attempt",
        "an anomaly is raised for the device; segmentation policy may block the source (explicit approved rule)",
        "returns to normal when the source stops",
        "iot.malformed_protocol",
        7,
        "identify the source and isolate it; inspect the target device health"
    ),
    m!(
        "branch_loss",
        "Branch connector loss",
        "the branch product or edge peer is unreachable",
        "none: the edge keeps enforcing locally",
        "branch inventory enrichment and branch-side enforcement updates pause",
        "the last pulled branch inventory remains; segmentation keeps the last verified policy (fail static)",
        "resynchronises when the branch connection returns",
        "iot.branch_unreachable",
        5,
        "check the branch appliance and its connectivity"
    ),
    m!(
        "policy_stale",
        "Policy stale",
        "the applied configuration has not been confirmed current within the staleness window",
        "none: the last verified policy keeps being enforced",
        "recent policy changes are not yet in force",
        "fail static: last known good policy and zones continue; the node reports staleness in heartbeats",
        "the next successful configuration sync clears it",
        "iot.policy_stale",
        6,
        "check platform reachability from the edge and pending configuration errors"
    ),
    m!(
        "graph_lag",
        "Graph lag",
        "the dependency graph was rebuilt longer ago than the lag threshold",
        "none",
        "impact analysis may miss recent communications",
        "queries answer from the last graph and report its age",
        "the next rebuild catches up",
        "iot.graph_lag",
        3,
        "check worker health and database load"
    ),
    m!(
        "risk_feed_stale",
        "Risk feed stale",
        "the vulnerability / threat feed was not refreshed within its freshness window",
        "none: risk never blocks by itself",
        "new vulnerabilities are not reflected in risk scores",
        "scores keep the last feed and expose the feed version and age; risk-based policy operands expire (fail secure)",
        "a successful feed refresh re-scores devices",
        "iot.risk_feed_stale",
        4,
        "check the feed connector credentials and connectivity"
    ),
    m!(
        "cloud_outage",
        "Cloud outage",
        "the control plane or the platform is unreachable from the edge",
        "none: OT traffic continues under the last policy",
        "no new policy, inventory or alerts until reconnection",
        "the edge enforces the persisted last verified configuration, queues observations and logs within bounded buffers",
        "queued data is shipped on reconnection; configuration resyncs",
        "iot.cloud_unreachable",
        7,
        "restore WAN/platform connectivity; check the queue backlog"
    ),
    m!(
        "site_isolation",
        "Site isolation",
        "neither the cloud nor peer sites/branch are reachable from the site",
        "none: local enforcement continues",
        "the site is unmanaged until reconnection",
        "local enforcement and capture continue; buffers bound memory and disk; oldest telemetry is dropped first",
        "automatic resynchronisation",
        "iot.site_isolated",
        8,
        "restore site connectivity; review dropped telemetry counters"
    ),
    m!(
        "time_skew",
        "Clock skew",
        "edge clock differs from the platform clock by more than the skew threshold (token and heartbeat timestamps)",
        "none",
        "token validation and event ordering may fail; schedules and exception windows shift",
        "observations are re-stamped with server receipt time when skew exceeds the threshold; token refresh is retried",
        "fix NTP; automatic afterwards",
        "iot.time_skew",
        5,
        "configure NTP on the edge host"
    ),
    m!(
        "storage_backlog",
        "Storage backlog",
        "observation or log queues above the high-water mark",
        "none",
        "telemetry delay; under sustained backlog the oldest telemetry is dropped",
        "backpressure: batches are rejected with retry-after; edge queues are bounded and drop oldest",
        "drains when the backlog clears",
        "iot.storage_backlog",
        5,
        "add database or worker capacity; check slow queries"
    ),
    m!(
        "upgrade_interruption",
        "Upgrade interruption",
        "an edge upgrade did not complete (pending marker left, version unchanged after the deadline)",
        "none: the previous version keeps running",
        "security fixes in the new version are not applied",
        "rollback to the running version; the upgrade error is reported in the next heartbeat",
        "retry the upgrade in the next window",
        "iot.upgrade_failed",
        6,
        "check the upgrade error and retry or pin the version"
    ),
];

pub fn mode(key: &str) -> Option<&'static Mode> {
    MODES.iter().find(|m| m.key == key)
}

/// Measured health (control plane or edge).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Health {
    #[serde(default)]
    pub sensor_silent_secs: Option<i64>,
    #[serde(default)]
    pub capture_drop_ratio: f64,
    #[serde(default)]
    pub duplicate_ratio: f64,
    #[serde(default)]
    pub ip_changes_last_hour: u64,
    #[serde(default)]
    pub randomized_macs_last_hour: u64,
    #[serde(default)]
    pub ambiguous_devices: u64,
    #[serde(default)]
    pub parser_failures: u64,
    #[serde(default)]
    pub malformed_per_minute: f64,
    #[serde(default = "yes")]
    pub branch_reachable: bool,
    #[serde(default)]
    pub policy_age_secs: Option<i64>,
    #[serde(default)]
    pub graph_age_secs: Option<i64>,
    #[serde(default)]
    pub risk_feed_age_secs: Option<i64>,
    #[serde(default = "yes")]
    pub cloud_reachable: bool,
    #[serde(default)]
    pub clock_skew_secs: i64,
    #[serde(default)]
    pub backlog_pct: u8,
    #[serde(default)]
    pub upgrade_interrupted: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub sensor_timeout_secs: i64,
    pub drop_ratio: f64,
    pub duplicate_ratio: f64,
    pub ip_changes: u64,
    pub randomized_macs: u64,
    pub ambiguous_devices: u64,
    pub malformed_per_minute: f64,
    pub policy_stale_secs: i64,
    pub graph_lag_secs: i64,
    pub risk_feed_secs: i64,
    pub clock_skew_secs: i64,
    pub backlog_pct: u8,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            sensor_timeout_secs: 300,
            drop_ratio: 0.01,
            duplicate_ratio: 0.5,
            ip_changes: 50,
            randomized_macs: 20,
            ambiguous_devices: 1,
            malformed_per_minute: 10.0,
            policy_stale_secs: 900,
            graph_lag_secs: 3600,
            risk_feed_secs: 7 * 86_400,
            clock_skew_secs: 120,
            backlog_pct: 80,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Active {
    pub mode: &'static Mode,
    pub measured: String,
}

pub fn evaluate(h: &Health, t: &Thresholds) -> Vec<Active> {
    let mut out = vec![];
    let mut add = |k: &str, measured: String| {
        if let Some(m) = mode(k) {
            out.push(Active { mode: m, measured });
        }
    };
    if let Some(s) = h.sensor_silent_secs.filter(|s| *s > t.sensor_timeout_secs) {
        add("sensor_loss", format!("silent for {s} s"));
    }
    if h.capture_drop_ratio > t.drop_ratio {
        add("packet_loss", format!("drop ratio {:.3}", h.capture_drop_ratio));
    }
    if h.duplicate_ratio > t.duplicate_ratio {
        add("duplicate_observations", format!("duplicate ratio {:.2}", h.duplicate_ratio));
    }
    if h.ip_changes_last_hour > t.ip_changes {
        add("ip_change", format!("{} address changes in the last hour", h.ip_changes_last_hour));
    }
    if h.randomized_macs_last_hour > t.randomized_macs {
        add("mac_randomization", format!("{} randomised MACs in the last hour", h.randomized_macs_last_hour));
    }
    if h.ambiguous_devices >= t.ambiguous_devices && h.ambiguous_devices > 0 {
        add("classification_ambiguity", format!("{} devices with ambiguous classification", h.ambiguous_devices));
    }
    if h.parser_failures > 0 {
        add("parser_crash", format!("{} parser failures", h.parser_failures));
    }
    if h.malformed_per_minute > t.malformed_per_minute {
        add("malformed_industrial_packet", format!("{:.1} malformed messages per minute", h.malformed_per_minute));
    }
    if !h.branch_reachable {
        add("branch_loss", "branch connector unreachable".into());
    }
    if let Some(a) = h.policy_age_secs.filter(|a| *a > t.policy_stale_secs) {
        add("policy_stale", format!("configuration unconfirmed for {a} s"));
    }
    if let Some(a) = h.graph_age_secs.filter(|a| *a > t.graph_lag_secs) {
        add("graph_lag", format!("graph built {a} s ago"));
    }
    if let Some(a) = h.risk_feed_age_secs.filter(|a| *a > t.risk_feed_secs) {
        add("risk_feed_stale", format!("feed refreshed {a} s ago"));
    }
    if !h.cloud_reachable {
        add("cloud_outage", "control plane unreachable".into());
    }
    if !h.cloud_reachable && !h.branch_reachable {
        add("site_isolation", "no control-plane or branch connectivity".into());
    }
    if h.clock_skew_secs.abs() > t.clock_skew_secs {
        add("time_skew", format!("clock skew {} s", h.clock_skew_secs));
    }
    if h.backlog_pct >= t.backlog_pct {
        add("storage_backlog", format!("backlog {}%", h.backlog_pct));
    }
    if h.upgrade_interrupted {
        add("upgrade_interruption", "upgrade did not complete".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_is_complete() {
        assert_eq!(MODES.len(), 17);
        let mut keys = std::collections::HashSet::new();
        for m in MODES {
            assert!(keys.insert(m.key));
            for s in [m.detection, m.safety_impact, m.security_impact, m.fallback, m.recovery, m.alert, m.operator_action] {
                assert!(!s.is_empty(), "{} has an empty field", m.key);
            }
            assert!(m.alert.starts_with("iot."));
        }
    }

    #[test]
    fn every_mode_is_detected() {
        let t = Thresholds::default();
        assert!(evaluate(&Health { branch_reachable: true, cloud_reachable: true, ..Default::default() }, &t).is_empty());
        let bad = Health {
            sensor_silent_secs: Some(9999),
            capture_drop_ratio: 0.2,
            duplicate_ratio: 0.9,
            ip_changes_last_hour: 100,
            randomized_macs_last_hour: 100,
            ambiguous_devices: 4,
            parser_failures: 1,
            malformed_per_minute: 50.0,
            branch_reachable: false,
            policy_age_secs: Some(5000),
            graph_age_secs: Some(9000),
            risk_feed_age_secs: Some(30 * 86_400),
            cloud_reachable: false,
            clock_skew_secs: -600,
            backlog_pct: 95,
            upgrade_interrupted: true,
        };
        let active = evaluate(&bad, &t);
        let keys: std::collections::HashSet<&str> = active.iter().map(|a| a.mode.key).collect();
        for m in MODES {
            assert!(keys.contains(m.key), "{} not detected", m.key);
        }
    }
}
