//! Segmentation: zones, device groups, assignment, quarantine, temporary
//! exceptions, enforcement decisions, simulation, recommendations and
//! host rule rendering (ZTE-IOT sections 70 Segmentation Architecture, 71
//! Device Segment Assignment, 72 Dynamic Segmentation, 73 Quarantine
//! Segment, 74 IoT Microsegmentation, 75 OT Zone/Conduit Policy, 76
//! East-West, 77 North-South, 78 Internet Access, 81 Branch Enforcement,
//! 83 Policy Simulation, 85 Exception Workflow, 129 Segmentation
//! Certification; ZTE-IOTINV-153162/153163/153167/153168; AE-IOT-0006
//! policy recommendations from high-confidence devices, AE-IOT-0012 zones
//! and conduits).
//!
//! * **Assignment.** Groups match devices on type, category, vendor,
//!   model, site, tags and risk, in priority order. A group marked
//!   `privileged` (or a zone with security level 3+) only admits devices
//!   classified with at least the group's minimum confidence; uncertain
//!   devices fall to the observation group, unknown devices to quarantine
//!   — uncertainty never grants a privileged segment.
//! * **Decisions.** The tenant's compiled `iot.segmentation` policy (from
//!   the platform) is evaluated with `aether-core`; an active temporary
//!   exception matching the flow allows it. The zone's enforcement mode
//!   turns blocks into logged "would block" decisions while observing or
//!   simulating. Risk alone never blocks a safety-sensitive device unless
//!   the deciding rule is an explicit, approved policy rule (never the
//!   default action or an automatic quarantine).
//! * **Fail static.** Loss of the control plane keeps the last verified
//!   policy and zone configuration in force (the edge persists it);
//!   segmentation never silently collapses to allow-all.

use crate::baseline::Baseline;
use crate::policy::{segmentation_context, DeviceCtx, FlowCtx};
use crate::protocols::OpClass;
use aether_core::policy::eval::{Decision, PreparedPolicy};
use aether_core::policy::{Condition, Op, Rule, RuleSet};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const QUARANTINE_GROUP: &str = "quarantine";
pub const OBSERVE_GROUP: &str = "unclassified";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Decisions are computed and logged; nothing is blocked.
    Observe,
    /// Blocks are reported as "would block" (pre-enforcement validation).
    Simulate,
    Enforce,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "observe" => Some(Mode::Observe),
            "simulate" => Some(Mode::Simulate),
            "enforce" => Some(Mode::Enforce),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub key: String,
    /// IEC 62443 target security level 1..4.
    pub security_level: u8,
    pub mode: Mode,
    /// Safety-critical zone: blocks require an approved explicit rule.
    #[serde(default)]
    pub safety_critical: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GroupMatch {
    #[serde(default)]
    pub device_types: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub vendors: Vec<String>,
    /// Glob over the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub sites: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub risk_levels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub priority: i32,
    pub matcher: GroupMatch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default)]
    pub privileged: bool,
    /// Minimum classification confidence (0..1); privileged groups default to 0.9.
    #[serde(default)]
    pub min_confidence: f64,
}

/// What assignment needs to know about a device.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceFacts {
    pub id: String,
    pub device_type: String,
    pub category: String,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    pub confidence: f64,
    #[serde(default)]
    pub quarantined: bool,
    /// Administrator-pinned groups (manual assignment).
    #[serde(default)]
    pub pinned_groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assignment {
    pub groups: Vec<String>,
    pub zone: Option<String>,
    pub reasons: Vec<String>,
    /// Groups the device matched but was refused for low confidence.
    pub withheld: Vec<String>,
}

fn any_eq(list: &[String], v: Option<&str>) -> bool {
    list.is_empty() || v.map(|v| list.iter().any(|x| x.eq_ignore_ascii_case(v))).unwrap_or(false)
}

fn glob(p: &str, s: &str) -> bool {
    let rule = crate::classify::Rule {
        id: String::new(),
        source: "dns".into(),
        field: "q".into(),
        kind: crate::classify::Match::Glob,
        pattern: p.into(),
        device_type: None,
        vendor: None,
        model: None,
        os: None,
        weight: 0.5,
        origin: String::new(),
    };
    rule.matches(&crate::classify::Fact { source: "dns".into(), field: "q".into(), value: s.into() })
}

impl GroupMatch {
    pub fn is_empty(&self) -> bool {
        self.device_types.is_empty()
            && self.categories.is_empty()
            && self.vendors.is_empty()
            && self.model.is_none()
            && self.sites.is_empty()
            && self.tags.is_empty()
            && self.risk_levels.is_empty()
    }
    pub fn matches(&self, d: &DeviceFacts) -> bool {
        !self.is_empty()
            && any_eq(&self.device_types, Some(&d.device_type))
            && any_eq(&self.categories, Some(&d.category))
            && any_eq(&self.vendors, d.vendor.as_deref())
            && self.model.as_deref().map(|p| d.model.as_deref().map(|m| glob(p, m)).unwrap_or(false)).unwrap_or(true)
            && any_eq(&self.sites, d.site.as_deref())
            && (self.tags.is_empty() || self.tags.iter().any(|t| d.tags.contains(t)))
            && any_eq(&self.risk_levels, d.risk_level.as_deref())
    }
}

/// Assign a device to groups and a zone.
pub fn assign(d: &DeviceFacts, groups: &[Group], zones: &[Zone]) -> Assignment {
    let mut sorted: Vec<&Group> = groups.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.key.cmp(&b.key)));
    let zone_of = |g: &Group| g.zone.as_ref().and_then(|z| zones.iter().find(|x| &x.id == z || &x.key == z));
    if d.quarantined {
        let q = groups.iter().find(|g| g.key == QUARANTINE_GROUP);
        return Assignment {
            groups: q.map(|g| vec![g.id.clone()]).unwrap_or_default(),
            zone: q.and_then(|g| g.zone.clone()),
            reasons: vec!["device is quarantined".into()],
            withheld: vec![],
        };
    }
    let mut out = Assignment { groups: vec![], zone: None, reasons: vec![], withheld: vec![] };
    for p in &d.pinned_groups {
        if let Some(g) = groups.iter().find(|g| &g.id == p || &g.key == p) {
            out.groups.push(g.id.clone());
            out.reasons.push(format!("pinned to {}", g.key));
            if out.zone.is_none() {
                out.zone = g.zone.clone();
            }
        }
    }
    for g in sorted {
        if out.groups.contains(&g.id) || !g.matcher.matches(d) {
            continue;
        }
        let privileged = g.privileged || zone_of(g).map(|z| z.security_level >= 3).unwrap_or(false);
        let min = if privileged { g.min_confidence.max(0.9) } else { g.min_confidence };
        if d.confidence < min || d.device_type == "unknown" && privileged {
            out.withheld.push(g.id.clone());
            out.reasons.push(format!("withheld from {} (confidence {:.2} < {:.2})", g.key, d.confidence, min));
            continue;
        }
        out.groups.push(g.id.clone());
        out.reasons.push(format!("matched {}", g.key));
        if out.zone.is_none() {
            out.zone = g.zone.clone();
        }
    }
    if out.groups.is_empty() {
        let fallback = if d.device_type == "unknown" { QUARANTINE_GROUP } else { OBSERVE_GROUP };
        if let Some(g) = groups.iter().find(|g| g.key == fallback) {
            out.groups.push(g.id.clone());
            out.zone = g.zone.clone();
            out.reasons.push(format!("no confident group match; placed in {fallback}"));
        }
    }
    out
}

/// A temporary exception allowing a specific communication until expiry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exception {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Highest operation class permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_op: Option<OpClass>,
    pub starts_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Exception {
    pub fn active(&self, at: DateTime<Utc>) -> bool {
        at >= self.starts_at && at < self.expires_at
    }
    pub fn matches(&self, f: &FlowCtx, at: DateTime<Utc>) -> bool {
        let dev = |want: &Option<String>, d: &DeviceCtx| want.as_ref().map(|w| d.device_id.as_deref() == Some(w.as_str())).unwrap_or(true);
        let grp = |want: &Option<String>, d: &DeviceCtx| want.as_ref().map(|w| d.groups.contains(w)).unwrap_or(true);
        let specific = self.source_device.is_some() || self.destination_device.is_some() || self.source_group.is_some() || self.destination_group.is_some();
        specific
            && self.active(at)
            && dev(&self.source_device, &f.source)
            && dev(&self.destination_device, &f.destination)
            && grp(&self.source_group, &f.source)
            && grp(&self.destination_group, &f.destination)
            && self.protocol.as_ref().map(|p| f.protocol.as_deref() == Some(p.as_str())).unwrap_or(true)
            && self.port.map(|p| f.port == Some(p)).unwrap_or(true)
            && self.max_op.map(|m| f.operation_class.as_deref().and_then(op_class).map(|o| o <= m).unwrap_or(false)).unwrap_or(true)
    }
    pub fn validate(&self, max_days: i64) -> Result<(), &'static str> {
        if self.expires_at <= self.starts_at {
            return Err("expiry_before_start");
        }
        if self.expires_at - self.starts_at > chrono::Duration::days(max_days) {
            return Err("exception_too_long");
        }
        if self.source_device.is_none() && self.destination_device.is_none() && self.source_group.is_none() && self.destination_group.is_none() {
            return Err("exception_too_broad");
        }
        Ok(())
    }
}

pub fn op_class(s: &str) -> Option<OpClass> {
    crate::protocols::OP_CLASSES.iter().position(|x| *x == s).map(|i| match i {
        0 => OpClass::Session,
        1 => OpClass::Read,
        2 => OpClass::Diagnostic,
        3 => OpClass::Write,
        4 => OpClass::Control,
        5 => OpClass::Program,
        _ => OpClass::Firmware,
    })
}

/// Outcome of one enforcement decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// What the enforcement point does: allow or block.
    pub enforced: String,
    /// What policy decided (allow/alert/block/quarantine).
    pub policy_action: String,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
    pub alert: bool,
    pub quarantine_source: bool,
    pub reason: String,
    pub fail_secure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}

/// Decide a flow.
pub fn decide(policy: Option<&PreparedPolicy>, exceptions: &[Exception], zones: &[Zone], f: &FlowCtx, at: DateTime<Utc>) -> Verdict {
    let zone = f.destination.zone.as_ref().and_then(|z| zones.iter().find(|x| &x.id == z || &x.key == z));
    let mode = zone.map(|z| z.mode).unwrap_or(Mode::Enforce);
    if let Some(e) = exceptions.iter().find(|e| e.matches(f, at)) {
        return Verdict {
            enforced: "allow".into(),
            policy_action: "allow".into(),
            mode,
            rule_id: None,
            rule_name: None,
            exception_id: Some(e.id.clone()),
            alert: false,
            quarantine_source: false,
            reason: "temporary exception".into(),
            fail_secure: false,
            policy_revision: None,
            policy_hash: None,
        };
    }
    let Some(p) = policy else {
        // No policy distributed yet: observe only (never block blindly).
        return Verdict {
            enforced: "allow".into(),
            policy_action: "alert".into(),
            mode: Mode::Observe,
            rule_id: None,
            rule_name: None,
            exception_id: None,
            alert: false,
            quarantine_source: false,
            reason: "no segmentation policy loaded".into(),
            fail_secure: false,
            policy_revision: None,
            policy_hash: None,
        };
    };
    let mut ctx = segmentation_context(f);
    ctx.at = Some(at);
    let d: Decision = p.evaluate(&ctx, false);
    let restrictive = matches!(d.action.as_str(), "block" | "quarantine");
    let explicit = d.rule_id.is_some() && !d.fail_secure;
    let safety = zone.map(|z| z.safety_critical).unwrap_or(false) || f.destination.safety_sensitive;
    let (enforced, reason) = if !restrictive {
        ("allow", format!("{} by {}", d.action, d.rule_name.clone().unwrap_or_else(|| "default action".into())))
    } else if safety && !explicit {
        ("allow", "safety-sensitive destination: only an explicit approved rule may block".to_string())
    } else if mode != Mode::Enforce {
        ("allow", format!("would {} ({:?} mode)", d.action, mode).to_ascii_lowercase())
    } else {
        ("block", format!("{} by {}", d.action, d.rule_name.clone().unwrap_or_else(|| "default action".into())))
    };
    Verdict {
        enforced: enforced.into(),
        policy_action: d.action.clone(),
        mode,
        rule_id: d.rule_id,
        rule_name: d.rule_name.clone(),
        exception_id: None,
        alert: d.action == "alert" || (restrictive && enforced == "allow"),
        quarantine_source: d.action == "quarantine" && enforced == "block" && !f.source.safety_sensitive,
        reason,
        fail_secure: d.fail_secure,
        policy_revision: Some(d.revision),
        policy_hash: Some(d.content_hash.clone()),
    }
}

/// Simulation result over observed flows (section 83).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Simulation {
    pub flows: usize,
    pub allowed: usize,
    pub alerted: usize,
    pub would_block: usize,
    pub safety_critical_blocks: usize,
    pub by_rule: BTreeMap<String, usize>,
    pub samples: Vec<serde_json::Value>,
    /// Blocking safety-critical traffic requires a staged rollout.
    pub requires_staged_rollout: bool,
}

pub fn simulate(policy: &PreparedPolicy, exceptions: &[Exception], flows: &[FlowCtx], at: DateTime<Utc>) -> Simulation {
    let mut s = Simulation { flows: flows.len(), ..Default::default() };
    let enforce_all: Vec<Zone> = vec![];
    for f in flows.iter().take(100_000) {
        let v = decide(Some(policy), exceptions, &enforce_all, f, at);
        let key = v.rule_name.clone().unwrap_or_else(|| if v.exception_id.is_some() { "exception".into() } else { "default".into() });
        *s.by_rule.entry(key).or_default() += 1;
        match v.policy_action.as_str() {
            "block" | "quarantine" => {
                s.would_block += 1;
                if f.destination.safety_sensitive {
                    s.safety_critical_blocks += 1;
                }
                if s.samples.len() < 50 {
                    s.samples.push(json!({ "source": f.source.device_id, "destination": f.destination.device_id, "protocol": f.protocol, "operation_class": f.operation_class, "rule": v.rule_name }));
                }
            }
            "alert" => s.alerted += 1,
            _ => s.allowed += 1,
        }
    }
    s.requires_staged_rollout = s.safety_critical_blocks > 0;
    s
}

/// Recommended allow-list rule set for a destination group from the
/// baselines of high-confidence member devices (AE-IOT-0006): one allow
/// rule per (source group, protocol, highest operation class), then a
/// block of modifying operations from everyone else.
pub fn recommend(dest_group: &str, members: &[(String, f64, &Baseline)], peer_groups: &BTreeMap<String, Vec<String>>) -> RuleSet {
    let mut allow: BTreeMap<(String, String), OpClass> = BTreeMap::new();
    for (_, conf, b) in members {
        if *conf < 0.9 {
            continue;
        }
        for (k, st) in b.edges.values() {
            if k.outbound {
                continue;
            }
            let groups = peer_groups.get(&k.peer).cloned().unwrap_or_default();
            for g in groups {
                let proto = st.protocol.clone().unwrap_or_else(|| "other".into());
                let e = allow.entry((g, proto)).or_insert(OpClass::Session);
                if let Some(op) = st.max_op {
                    if op > *e {
                        *e = op;
                    }
                }
            }
        }
    }
    let mut rules = vec![];
    let mut order = 10;
    let dg = json!(dest_group);
    for ((g, proto), op) in &allow {
        let ops: Vec<serde_json::Value> = crate::protocols::OP_CLASSES.iter().filter(|x| op_class(x).map(|c| c <= *op).unwrap_or(false)).map(|x| json!(x)).collect();
        rules.push(Rule {
            id: crate::stable_uuid(&format!("{dest_group}|{g}|{proto}")),
            name: format!("Allow {proto} up to {} from group {g}", op.as_str()),
            description: "recommended from the learned baseline".into(),
            order,
            enabled: true,
            condition: Condition::All(vec![
                Condition::pred("destination.device_group", Op::In, vec![dg.clone()]),
                Condition::pred("source.device_group", Op::In, vec![json!(g)]),
                Condition::pred("network.protocol", Op::In, vec![json!(proto)]),
                Condition::pred("network.operation_class", Op::In, ops),
            ]),
            action: "allow".into(),
            params: Default::default(),
            schedule: Default::default(),
            emergency: false,
            labels: vec!["recommended".into()],
        });
        order += 10;
    }
    rules.push(Rule {
        id: crate::stable_uuid(&format!("{dest_group}|block-modifying")),
        name: "Block other modifying operations".into(),
        description: "recommended: writes, control, program and firmware operations only from learned peers".into(),
        order,
        enabled: true,
        condition: Condition::All(vec![
            Condition::pred("destination.device_group", Op::In, vec![dg]),
            Condition::pred("network.operation_class", Op::In, vec![json!("write"), json!("control"), json!("program"), json!("firmware")]),
        ]),
        action: "block".into(),
        params: Default::default(),
        schedule: Default::default(),
        emergency: false,
        labels: vec!["recommended".into()],
    });
    RuleSet { policy_type: crate::policy::SEGMENTATION.into(), default_action: "alert".into(), default_params: Default::default(), rules }
}

/// Render address-level rules as an nftables ruleset for host enforcement
/// on the edge appliance (bridge/router mode). `members` maps group id →
/// member IP addresses; rules are (source group, destination group,
/// transport, port, verdict) resolved from the policy and baselines.
pub fn render_nftables(members: &BTreeMap<String, BTreeSet<String>>, rules: &[(String, String, String, u16, bool)], default_drop: bool) -> String {
    let set_name = |g: &str| {
        let a: Vec<char> = g.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        format!("g_{}", a[a.len().saturating_sub(24)..].iter().collect::<String>())
    };
    let mut out = String::from("# Generated by aether-iot edge. Do not edit.\ntable inet aether_iot {\n");
    for (g, ips) in members {
        let v4: Vec<&String> = ips.iter().filter(|i| i.parse::<std::net::Ipv4Addr>().is_ok()).collect();
        out.push_str(&format!("  set {} {{\n    type ipv4_addr\n", set_name(g)));
        if !v4.is_empty() {
            out.push_str(&format!("    elements = {{ {} }}\n", v4.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
        out.push_str("  }\n");
    }
    out.push_str(&format!(
        "  chain forward {{\n    type filter hook forward priority 0; policy {};\n    ct state established,related accept\n",
        if default_drop { "drop" } else { "accept" }
    ));
    for (src, dst, transport, port, allow) in rules {
        if !members.contains_key(src) || !members.contains_key(dst) || !matches!(transport.as_str(), "tcp" | "udp") {
            continue;
        }
        let ports = if *port == 0 { format!("meta l4proto {transport}") } else { format!("{transport} dport {port}") };
        out.push_str(&format!("    ip saddr @{} ip daddr @{} {} {}\n", set_name(src), set_name(dst), ports, if *allow { "accept" } else { "drop" }));
    }
    out.push_str("  }\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_core::policy::compile::{compile, Target};

    const EWS: &str = "00000000-0000-0000-0000-0000000000e5";
    const HMIS: &str = "00000000-0000-0000-0000-0000000000a1";
    const PLCS: &str = "00000000-0000-0000-0000-0000000000b1";

    fn zone(key: &str, sl: u8, mode: Mode, safety: bool) -> Zone {
        Zone { id: key.into(), key: key.into(), security_level: sl, mode, safety_critical: safety }
    }

    fn group(key: &str, prio: i32, m: GroupMatch, zone: &str, privileged: bool) -> Group {
        Group { id: key.into(), key: key.into(), priority: prio, matcher: m, zone: Some(zone.into()), privileged, min_confidence: 0.0 }
    }

    fn dev(ty: &str, cat: &str, conf: f64) -> DeviceFacts {
        DeviceFacts { id: "d1".into(), device_type: ty.into(), category: cat.into(), confidence: conf, ..Default::default() }
    }

    #[test]
    fn uncertain_devices_never_get_privileged_groups() {
        let zones = vec![zone("ot_control", 3, Mode::Enforce, true), zone("iot", 1, Mode::Enforce, false), zone("quarantine", 1, Mode::Enforce, false)];
        let groups = vec![
            group("plcs", 100, GroupMatch { device_types: vec!["plc".into()], ..Default::default() }, "ot_control", true),
            group("cameras", 50, GroupMatch { categories: vec!["physical_security".into()], ..Default::default() }, "iot", false),
            group(QUARANTINE_GROUP, 0, GroupMatch::default(), "quarantine", false),
            group(OBSERVE_GROUP, 0, GroupMatch::default(), "iot", false),
        ];
        let a = assign(&dev("plc", "industrial_control", 0.95), &groups, &zones);
        assert_eq!((a.groups.clone(), a.zone.as_deref()), (vec!["plcs".to_string()], Some("ot_control")));
        let b = assign(&dev("plc", "industrial_control", 0.6), &groups, &zones);
        assert_eq!(b.groups, vec![OBSERVE_GROUP.to_string()]);
        assert_eq!(b.withheld, vec!["plcs".to_string()]);
        let u = assign(&dev("unknown", "unknown", 0.2), &groups, &zones);
        assert_eq!(u.groups, vec![QUARANTINE_GROUP.to_string()]);
        let mut q = dev("ip_camera", "physical_security", 0.99);
        q.quarantined = true;
        assert_eq!(assign(&q, &groups, &zones).groups, vec![QUARANTINE_GROUP.to_string()]);
        let mut p = dev("unknown", "unknown", 0.1);
        p.pinned_groups = vec!["cameras".into()];
        assert_eq!(assign(&p, &groups, &zones).groups, vec!["cameras".to_string()]);
    }

    fn policy() -> PreparedPolicy {
        let t = crate::policy::types().into_iter().find(|t| t.key == crate::policy::SEGMENTATION).unwrap();
        let rs = RuleSet {
            policy_type: t.key.clone(),
            default_action: "alert".into(),
            default_params: Default::default(),
            rules: vec![Rule {
                id: Uuid::now_v7(),
                name: "no writes to PLCs".into(),
                description: String::new(),
                order: 10,
                enabled: true,
                condition: Condition::All(vec![
                    Condition::pred("destination.device_type", Op::In, vec![json!("plc")]),
                    Condition::pred("network.operation_class", Op::In, vec![json!("write"), json!("program")]),
                    Condition::pred("source.device_group", Op::NotIn, vec![json!(EWS)]),
                ]),
                action: "block".into(),
                params: Default::default(),
                schedule: Default::default(),
                emergency: false,
                labels: vec![],
            }],
        };
        PreparedPolicy::new(compile(&t, &rs, Target { tenant_id: Uuid::nil(), policy_set_id: Uuid::now_v7(), revision: 3 }).unwrap())
    }

    fn write_flow(zone: &str) -> FlowCtx {
        FlowCtx {
            source: DeviceCtx { device_id: Some("hmi".into()), groups: vec![HMIS.into()], ..Default::default() },
            destination: DeviceCtx { device_id: Some("plc".into()), device_type: Some("plc".into()), zone: Some(zone.into()), safety_sensitive: true, ..Default::default() },
            protocol: Some("modbus".into()),
            operation_class: Some("write".into()),
            port: Some(502),
            ..Default::default()
        }
    }

    #[test]
    fn decisions_modes_exceptions_and_safety() {
        let p = policy();
        let now = Utc::now();
        let zones = vec![zone("enf", 3, Mode::Enforce, true), zone("obs", 3, Mode::Observe, true)];
        let v = decide(Some(&p), &[], &zones, &write_flow("enf"), now);
        assert_eq!((v.enforced.as_str(), v.policy_action.as_str(), v.policy_revision), ("block", "block", Some(3)), "explicit approved rule blocks even safety-critical traffic");
        let o = decide(Some(&p), &[], &zones, &write_flow("obs"), now);
        assert_eq!((o.enforced.as_str(), o.alert), ("allow", true));
        assert!(o.reason.contains("would block"));
        let mut read = write_flow("enf");
        read.operation_class = Some("read".into());
        let r = decide(Some(&p), &[], &zones, &read, now);
        assert_eq!((r.enforced.as_str(), r.policy_action.as_str()), ("allow", "alert"));
        let ex = Exception {
            id: "ex1".into(),
            source_device: Some("hmi".into()),
            destination_device: Some("plc".into()),
            source_group: None,
            destination_group: None,
            protocol: Some("modbus".into()),
            port: Some(502),
            max_op: Some(OpClass::Write),
            starts_at: now - chrono::Duration::minutes(1),
            expires_at: now + chrono::Duration::hours(1),
        };
        assert!(ex.validate(30).is_ok());
        let e = decide(Some(&p), std::slice::from_ref(&ex), &zones, &write_flow("enf"), now);
        assert_eq!((e.enforced.as_str(), e.exception_id.as_deref()), ("allow", Some("ex1")));
        let expired = decide(Some(&p), std::slice::from_ref(&ex), &zones, &write_flow("enf"), now + chrono::Duration::hours(2));
        assert_eq!(expired.enforced, "block");
        let mut prog = write_flow("enf");
        prog.operation_class = Some("program".into());
        assert_eq!(decide(Some(&p), std::slice::from_ref(&ex), &zones, &prog, now).enforced, "block", "exception bounded by operation class");
        assert_eq!(decide(None, &[], &zones, &write_flow("enf"), now).enforced, "allow", "no policy: observe");
        let broad = Exception { source_device: None, destination_device: None, ..ex };
        assert_eq!(broad.validate(30), Err("exception_too_broad"));
    }

    #[test]
    fn simulation_and_recommendations() {
        let p = policy();
        let flows = vec![write_flow("enf"), FlowCtx { operation_class: Some("read".into()), ..write_flow("enf") }];
        let s = simulate(&p, &[], &flows, Utc::now());
        assert_eq!((s.would_block, s.alerted, s.safety_critical_blocks, s.requires_staged_rollout), (1, 1, 1, true));
        let mut b = Baseline::new(Utc::now());
        b.learn_edge(
            &crate::model::Flow {
                peer_ip: "10.0.0.9".into(),
                peer_mac: None,
                transport: "tcp".into(),
                port: 502,
                outbound: false,
                packets: 1,
                bytes: 1,
                protocol: Some(crate::protocols::Protocol::Modbus),
                max_op: Some(OpClass::Write),
                operations: vec![],
            },
            Utc::now(),
        );
        let peers: BTreeMap<String, Vec<String>> = [("10.0.0.9".to_string(), vec![HMIS.to_string()])].into_iter().collect();
        let rs = recommend(PLCS, &[("plc1".into(), 0.95, &b), ("plc2".into(), 0.5, &b)], &peers);
        assert_eq!(rs.rules.len(), 2);
        assert!(rs.rules[0].name.contains("modbus") && rs.rules[0].name.contains("write"));
        let t = crate::policy::types().into_iter().find(|t| t.key == crate::policy::SEGMENTATION).unwrap();
        assert!(compile(&t, &rs, Target { tenant_id: Uuid::nil(), policy_set_id: Uuid::now_v7(), revision: 1 }).is_ok(), "recommendations are valid policy");
        let members: BTreeMap<String, BTreeSet<String>> =
            [(HMIS.to_string(), ["10.0.0.9".to_string()].into_iter().collect()), (PLCS.to_string(), ["10.0.0.5".to_string()].into_iter().collect())].into_iter().collect();
        let nft = render_nftables(&members, &[(HMIS.into(), PLCS.into(), "tcp".into(), 502, true), ("x; drop table".into(), PLCS.into(), "tcp".into(), 1, true)], true);
        assert!(nft.contains("ip saddr @g_0000000000000000000000a1 ip daddr @g_0000000000000000000000b1 tcp dport 502 accept"), "{nft}");
        assert!(nft.contains("policy drop"));
        assert!(!nft.contains("drop table"), "unknown groups are never rendered");
    }
}
