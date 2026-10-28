//! Policy types registered with the platform and the evaluation contexts
//! built for them (ZTE-IOT sections 70–79 segmentation and access policy,
//! 82 Cloud Policy Distribution, 83 Policy Simulation, 108 Policy Apis;
//! Volume 2 "Segmentation Policy", "Access Mediation"; docs/integration.md
//! §5, §8a action owners and type extensions).
//!
//! * `iot.segmentation` — east-west and north-south device policy between
//!   device groups, zones, device types/categories, risk and confidence,
//!   by protocol, **operation class** (read/write/control/program/firmware)
//!   and port. Actions: allow, alert (allow and raise an alert), block,
//!   quarantine. The default action is `alert`: an empty policy observes
//!   without disrupting operations.
//! * `iot.remote_access` — privileged remote access to OT assets by vendor
//!   principals and users, conditioned on approval and just-in-time
//!   windows. Default deny.
//! * `iot.active_query` — governance of active interrogation techniques
//!   (passive by default; ZTE-IOTINV-153161). Default deny.
//! * an extension of the built-in `firewall.network` type with `iot.*`
//!   operands and the `iot_quarantine` action, so cloud firewall rules can
//!   reference device groups, zones, device types and device risk.
//!
//! Operands carrying volatile context (risk, confidence) declare a maximum
//! age: stale context is unknown, and unknown context never matches a
//! permissive rule (fail-secure evaluation in `aether-core`).

use crate::protocols::{ALL_PROTOCOLS, OP_CLASSES};
use crate::taxonomy;
use aether_core::policy::{ActionDef, Context, Op, OperandDef, ParamDef, PolicyType, TypeExtension, ValueType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SEGMENTATION: &str = "iot.segmentation";
pub const REMOTE_ACCESS: &str = "iot.remote_access";
pub const ACTIVE_QUERY: &str = "iot.active_query";
pub const PRODUCT: &str = "iot";

const SET: &[Op] = &[Op::In, Op::NotIn, Op::Exists, Op::NotExists];
const STR: &[Op] = &[Op::In, Op::NotIn, Op::Eq, Op::Ne, Op::Glob, Op::Exists, Op::NotExists];
const NUM: &[Op] = &[Op::Eq, Op::Ne, Op::Lt, Op::Lte, Op::Gt, Op::Gte, Op::In, Op::NotIn];
const IP: &[Op] = &[Op::Cidr, Op::NotCidr, Op::Exists, Op::NotExists];
const BOOL: &[Op] = &[Op::Eq, Op::Ne];
const TIME: &[Op] = &[Op::Within, Op::NotWithin];

fn od(name: &str, label: &str, vt: ValueType, multi: bool, ops: &[Op]) -> OperandDef {
    OperandDef { name: name.into(), label: label.into(), value_type: vt, multi, ops: ops.to_vec(), enum_values: vec![], ref_type: None, max_age_secs: None }
}
fn en(name: &str, label: &str, multi: bool, values: &[&str]) -> OperandDef {
    OperandDef { enum_values: values.iter().map(|s| s.to_string()).collect(), ..od(name, label, ValueType::Enum, multi, SET) }
}
fn rf(name: &str, label: &str, multi: bool, ref_type: &str) -> OperandDef {
    OperandDef { ref_type: Some(ref_type.into()), ..od(name, label, ValueType::Ref, multi, SET) }
}
fn fresh(mut o: OperandDef, secs: i64) -> OperandDef {
    o.max_age_secs = Some(secs);
    o
}
fn act(key: &str, label: &str, permissive: bool, params: Vec<ParamDef>) -> ActionDef {
    ActionDef { key: key.into(), label: label.into(), permissive, params }
}
fn param(name: &str, vt: ValueType, required: bool) -> ParamDef {
    ParamDef { name: name.into(), value_type: vt, required, enum_values: vec![], ref_type: None }
}

pub const RISK_LEVELS: &[&str] = &["low", "medium", "high", "critical"];
pub const TIERS: &[&str] = &["high", "medium", "low"];
pub const REMOTE_PROTOCOLS: &[&str] = &["rdp", "ssh", "vnc", "http", "https", "telnet", "vendor_tool"];
pub const QUERY_KINDS: &[&str] = &["icmp_ping", "tcp_port_check", "snmp_sysdescr", "modbus_device_id", "enip_list_identity", "bacnet_who_is", "s7_read_szl", "http_banner"];
pub const QUERY_RISK: &[&str] = &["safe", "caution", "intrusive"];

/// Ref types this product resolves (policy reference validation hook).
pub const REF_TYPES: &[(&str, &str)] =
    &[("iot.device_group", "device_groups"), ("iot.zone", "zones"), ("iot.site", "sites"), ("iot.vendor_principal", "vendor_principals"), ("iot.device", "assets")];

fn protocols() -> Vec<&'static str> {
    let mut v: Vec<&str> = ALL_PROTOCOLS.iter().map(|p| p.as_str()).collect();
    v.extend(["http", "https", "dns", "ntp", "ssh", "rdp", "smb", "other"]);
    v
}

fn side(prefix: &str, label: &str) -> Vec<OperandDef> {
    vec![
        rf(&format!("{prefix}.device_group"), &format!("{label} device groups"), true, "iot.device_group"),
        rf(&format!("{prefix}.zone"), &format!("{label} zone"), false, "iot.zone"),
        rf(&format!("{prefix}.site"), &format!("{label} site"), false, "iot.site"),
        rf(&format!("{prefix}.device"), &format!("{label} device"), false, "iot.device"),
        en(&format!("{prefix}.device_type"), &format!("{label} device type"), false, &taxonomy::type_keys()),
        en(&format!("{prefix}.device_category"), &format!("{label} device category"), false, &taxonomy::category_keys()),
        fresh(en(&format!("{prefix}.risk_level"), &format!("{label} device risk level"), false, RISK_LEVELS), 3600),
        fresh(en(&format!("{prefix}.confidence_tier"), &format!("{label} classification confidence"), false, TIERS), 86_400),
        od(&format!("{prefix}.quarantined"), &format!("{label} quarantined"), ValueType::Boolean, false, BOOL),
        od(&format!("{prefix}.ip"), &format!("{label} address"), ValueType::Ip, false, IP),
    ]
}

pub fn types() -> Vec<PolicyType> {
    let mut seg = side("source", "Source");
    seg.extend(side("destination", "Destination"));
    seg.extend([
        en("network.protocol", "Protocol", false, &protocols()),
        en("network.operation_class", "Operation class", false, OP_CLASSES),
        od("network.operation", "Operation (protocol:operation)", ValueType::String, false, STR),
        od("destination.port", "Destination port", ValueType::Integer, false, NUM),
        od("network.internet", "Internet destination", ValueType::Boolean, false, BOOL),
        od("time", "Time of day", ValueType::Time, false, TIME),
    ]);
    let mut ra = vec![
        rf("user.id", "User", false, "user"),
        rf("user.groups", "User groups", true, "group"),
        rf("iot.vendor", "Vendor principal", false, "iot.vendor_principal"),
        od("source.ip", "Source address", ValueType::Ip, false, IP),
        od("source.country", "Source country", ValueType::String, false, STR),
        fresh(en("risk.level", "User risk level", false, RISK_LEVELS), 900),
        en("remote.protocol", "Remote protocol", false, REMOTE_PROTOCOLS),
        od("access.approved", "Approved request", ValueType::Boolean, false, BOOL),
        od("access.window_active", "Within the approved window", ValueType::Boolean, false, BOOL),
        od("access.mfa", "Authenticated with MFA", ValueType::Boolean, false, BOOL),
        od("time", "Time of day", ValueType::Time, false, TIME),
    ];
    ra.extend(side("destination", "Target").into_iter().filter(|o| !o.name.ends_with(".ip")));
    let aq = vec![
        en("query.kind", "Active query", false, QUERY_KINDS),
        en("query.risk", "Query risk", false, QUERY_RISK),
        rf("destination.device_group", "Target device groups", true, "iot.device_group"),
        rf("destination.zone", "Target zone", false, "iot.zone"),
        rf("destination.site", "Target site", false, "iot.site"),
        en("destination.device_type", "Target device type", false, &taxonomy::type_keys()),
        en("destination.device_category", "Target device category", false, &taxonomy::category_keys()),
        od("destination.safety_sensitive", "Target is safety-sensitive", ValueType::Boolean, false, BOOL),
        od("time", "Time of day", ValueType::Time, false, TIME),
    ];
    vec![
        PolicyType {
            key: SEGMENTATION.into(),
            product: PRODUCT.into(),
            label: "IoT/OT segmentation".into(),
            operands: seg,
            actions: vec![
                act("allow", "Allow", true, vec![param("log", ValueType::Boolean, false)]),
                act("alert", "Allow and alert", true, vec![param("severity", ValueType::Integer, false), param("message", ValueType::String, false)]),
                act("block", "Block", false, vec![param("log", ValueType::Boolean, false)]),
                act("quarantine", "Block and quarantine the source device", false, vec![]),
            ],
            default_action: "alert".into(),
            max_rules: 5000,
        },
        PolicyType {
            key: REMOTE_ACCESS.into(),
            product: PRODUCT.into(),
            label: "OT privileged remote access".into(),
            operands: ra,
            actions: vec![
                act("allow", "Allow", true, vec![param("max_minutes", ValueType::Integer, false), param("record", ValueType::Boolean, false)]),
                act("require_approval", "Require approval", false, vec![param("approver_group", ValueType::String, false)]),
                act("deny", "Deny", false, vec![]),
            ],
            default_action: "deny".into(),
            max_rules: 2000,
        },
        PolicyType {
            key: ACTIVE_QUERY.into(),
            product: PRODUCT.into(),
            label: "Active interrogation governance".into(),
            operands: aq,
            actions: vec![act("allow", "Allow", true, vec![]), act("require_approval", "Require approval", false, vec![]), act("deny", "Deny", false, vec![])],
            default_action: "deny".into(),
            max_rules: 500,
        },
    ]
}

/// Registration body for `PUT /api/v1/policy-types/{key}`.
pub fn registration(t: &PolicyType) -> Value {
    serde_json::to_value(t).unwrap_or(Value::Null)
}

/// The `firewall.network` extension contributed by this product.
pub fn firewall_extension() -> TypeExtension {
    TypeExtension {
        product: PRODUCT.into(),
        operands: vec![
            rf("iot.source_device_group", "IoT source device groups", true, "iot.device_group"),
            rf("iot.destination_device_group", "IoT destination device groups", true, "iot.device_group"),
            rf("iot.source_zone", "IoT source zone", false, "iot.zone"),
            rf("iot.destination_zone", "IoT destination zone", false, "iot.zone"),
            en("iot.destination_device_type", "IoT destination device type", false, &taxonomy::type_keys()),
            en("iot.destination_device_category", "IoT destination device category", false, &taxonomy::category_keys()),
            fresh(en("iot.source_risk_level", "IoT source device risk", false, RISK_LEVELS), 3600),
            fresh(en("iot.destination_risk_level", "IoT destination device risk", false, RISK_LEVELS), 3600),
            en("iot.operation_class", "Industrial operation class", false, OP_CLASSES),
        ],
        actions: vec![act("iot_quarantine", "Block and quarantine the IoT device", false, vec![])],
    }
}

/// Actions this product carries out (`PUT /policy-types/{key}/action-owners`).
pub fn action_owners() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (SEGMENTATION, vec!["allow", "alert", "block", "quarantine"]),
        (REMOTE_ACCESS, vec!["allow", "require_approval", "deny"]),
        (ACTIVE_QUERY, vec!["allow", "require_approval", "deny"]),
    ]
}

/// What policy evaluation knows about one side of a flow.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceCtx {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_tier: Option<String>,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// When risk/confidence were computed (freshness checks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub safety_sensitive: bool,
}

fn put(ctx: &mut Context, name: &str, v: Option<Value>, observed: Option<DateTime<Utc>>) {
    if let Some(v) = v {
        let values = match v {
            Value::Array(a) => a,
            x => vec![x],
        };
        ctx.attrs.insert(name.into(), aether_core::policy::Attr { values, observed_at: observed });
    }
}

fn add_side(ctx: &mut Context, prefix: &str, d: &DeviceCtx) {
    put(ctx, &format!("{prefix}.device_group"), Some(json!(d.groups)), None);
    put(ctx, &format!("{prefix}.zone"), d.zone.clone().map(Value::from), None);
    put(ctx, &format!("{prefix}.site"), d.site.clone().map(Value::from), None);
    put(ctx, &format!("{prefix}.device"), d.device_id.clone().map(Value::from), None);
    put(ctx, &format!("{prefix}.device_type"), d.device_type.clone().map(Value::from), None);
    put(ctx, &format!("{prefix}.device_category"), d.category.clone().map(Value::from), None);
    put(ctx, &format!("{prefix}.risk_level"), d.risk_level.clone().map(Value::from), d.evaluated_at);
    put(ctx, &format!("{prefix}.confidence_tier"), d.confidence_tier.clone().map(Value::from), d.evaluated_at);
    put(ctx, &format!("{prefix}.quarantined"), Some(json!(d.quarantined)), None);
    put(ctx, &format!("{prefix}.ip"), d.ip.clone().map(Value::from), None);
}

/// One flow to decide.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowCtx {
    pub source: DeviceCtx,
    pub destination: DeviceCtx,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub internet: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<DateTime<Utc>>,
}

/// Evaluation context for `iot.segmentation`.
pub fn segmentation_context(f: &FlowCtx) -> Context {
    let mut c = Context::default();
    add_side(&mut c, "source", &f.source);
    add_side(&mut c, "destination", &f.destination);
    put(&mut c, "network.protocol", f.protocol.clone().map(Value::from), None);
    put(&mut c, "network.operation_class", f.operation_class.clone().map(Value::from), None);
    put(&mut c, "network.operation", f.operation.clone().map(Value::from), None);
    put(&mut c, "destination.port", f.port.map(|p| json!(p)), None);
    put(&mut c, "network.internet", Some(json!(f.internet)), None);
    c.at = f.at;
    c
}

/// Context of the `firewall.network` extension operands for a flow.
pub fn firewall_context(f: &FlowCtx) -> Context {
    let mut c = Context::default();
    put(&mut c, "iot.source_device_group", Some(json!(f.source.groups)), None);
    put(&mut c, "iot.destination_device_group", Some(json!(f.destination.groups)), None);
    put(&mut c, "iot.source_zone", f.source.zone.clone().map(Value::from), None);
    put(&mut c, "iot.destination_zone", f.destination.zone.clone().map(Value::from), None);
    put(&mut c, "iot.destination_device_type", f.destination.device_type.clone().map(Value::from), None);
    put(&mut c, "iot.destination_device_category", f.destination.category.clone().map(Value::from), None);
    put(&mut c, "iot.source_risk_level", f.source.risk_level.clone().map(Value::from), f.source.evaluated_at);
    put(&mut c, "iot.destination_risk_level", f.destination.risk_level.clone().map(Value::from), f.destination.evaluated_at);
    put(&mut c, "iot.operation_class", f.operation_class.clone().map(Value::from), None);
    put(&mut c, "destination.port", f.port.map(|p| json!(p)), None);
    put(&mut c, "source.ip", f.source.ip.clone().map(Value::from), None);
    put(&mut c, "destination.ip", f.destination.ip.clone().map(Value::from), None);
    c
}

/// Context for `iot.remote_access`.
pub fn remote_access_context(
    user: Option<&str>,
    groups: &[String],
    vendor: Option<&str>,
    protocol: &str,
    approved: bool,
    window_active: bool,
    mfa: bool,
    target: &DeviceCtx,
    at: DateTime<Utc>,
) -> Context {
    let mut c = Context::default();
    put(&mut c, "user.id", user.map(Value::from), None);
    put(&mut c, "user.groups", Some(json!(groups)), None);
    put(&mut c, "iot.vendor", vendor.map(Value::from), None);
    put(&mut c, "remote.protocol", Some(Value::from(protocol)), None);
    put(&mut c, "access.approved", Some(json!(approved)), None);
    put(&mut c, "access.window_active", Some(json!(window_active)), None);
    put(&mut c, "access.mfa", Some(json!(mfa)), None);
    add_side(&mut c, "destination", target);
    c.attrs.remove("destination.ip");
    c.at = Some(at);
    c
}

/// Context for `iot.active_query`.
pub fn active_query_context(kind: &str, risk: &str, target: &DeviceCtx, at: DateTime<Utc>) -> Context {
    let mut c = Context::default();
    put(&mut c, "query.kind", Some(Value::from(kind)), None);
    put(&mut c, "query.risk", Some(Value::from(risk)), None);
    put(&mut c, "destination.device_group", Some(json!(target.groups)), None);
    put(&mut c, "destination.zone", target.zone.clone().map(Value::from), None);
    put(&mut c, "destination.site", target.site.clone().map(Value::from), None);
    put(&mut c, "destination.device_type", target.device_type.clone().map(Value::from), None);
    put(&mut c, "destination.device_category", target.category.clone().map(Value::from), None);
    put(&mut c, "destination.safety_sensitive", Some(json!(target.safety_sensitive)), None);
    c.at = Some(at);
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_core::policy::compile::{compile, Target};
    use aether_core::policy::eval::PreparedPolicy;
    use aether_core::policy::{Condition, Rule, RuleSet};
    use uuid::Uuid;

    fn rule(order: i32, cond: Condition, action: &str) -> Rule {
        Rule {
            id: Uuid::now_v7(),
            name: format!("r{order}"),
            description: String::new(),
            order,
            enabled: true,
            condition: cond,
            action: action.into(),
            params: Default::default(),
            schedule: Default::default(),
            emergency: false,
            labels: vec![],
        }
    }

    #[test]
    fn types_compile_and_extension_is_namespaced() {
        let ts = types();
        assert_eq!(ts.len(), 3);
        let base = aether_core::policy::catalog::get("firewall.network").expect("built-in firewall.network");
        assert!(firewall_extension().check(&base, &[]).is_empty(), "{:?}", firewall_extension().check(&base, &[]));
        for t in &ts {
            assert!(t.key.starts_with("iot."));
            assert!(t.action(&t.default_action).is_some());
            assert!(aether_core::policy::catalog::check_type(t).is_empty(), "{:?}", aether_core::policy::catalog::check_type(t));
        }
    }

    #[test]
    fn segmentation_blocks_writes_and_fails_secure_on_stale_risk() {
        let t = types().into_iter().find(|t| t.key == SEGMENTATION).unwrap();
        let g = Uuid::now_v7().to_string();
        let rs = RuleSet {
            policy_type: SEGMENTATION.into(),
            default_action: "alert".into(),
            default_params: Default::default(),
            rules: vec![
                rule(
                    10,
                    Condition::All(vec![
                        Condition::pred("destination.device_category", Op::In, vec![json!("industrial_control")]),
                        Condition::pred("network.operation_class", Op::In, vec![json!("write"), json!("control"), json!("program"), json!("firmware")]),
                        Condition::pred("source.device_group", Op::NotIn, vec![json!(g)]),
                    ]),
                    "block",
                ),
                rule(20, Condition::pred("source.risk_level", Op::In, vec![json!("low"), json!("medium")]), "allow"),
            ],
        };
        let c = compile(&t, &rs, Target { tenant_id: Uuid::nil(), policy_set_id: Uuid::now_v7(), revision: 1 }).expect("compiles");
        let p = PreparedPolicy::new(c);
        let mut f = FlowCtx {
            source: DeviceCtx { groups: vec![], device_type: Some("workstation".into()), risk_level: Some("low".into()), evaluated_at: Some(Utc::now()), ..Default::default() },
            destination: DeviceCtx { category: Some("industrial_control".into()), device_type: Some("plc".into()), ..Default::default() },
            protocol: Some("modbus".into()),
            operation_class: Some("write".into()),
            port: Some(502),
            ..Default::default()
        };
        assert_eq!(p.evaluate(&segmentation_context(&f), false).action, "block");
        f.source.groups = vec![g.clone()];
        assert_eq!(p.evaluate(&segmentation_context(&f), false).action, "allow");
        // Read from anyone with fresh low risk: allowed; stale risk: permissive rule skipped -> default alert.
        f.source.groups.clear();
        f.operation_class = Some("read".into());
        assert_eq!(p.evaluate(&segmentation_context(&f), false).action, "allow");
        f.source.evaluated_at = Some(Utc::now() - chrono::Duration::hours(5));
        let d = p.evaluate(&segmentation_context(&f), false);
        assert_eq!(d.action, "alert");
        // Firewall extension context carries the same facts.
        assert!(firewall_context(&f).attrs.contains_key("iot.destination_device_type"));
        let ra = remote_access_context(Some("u"), &[], Some("v"), "rdp", true, true, true, &f.destination, Utc::now());
        assert!(ra.attrs.contains_key("access.window_active"));
        assert!(active_query_context("modbus_device_id", "caution", &f.destination, Utc::now()).attrs.contains_key("query.risk"));
    }
}
