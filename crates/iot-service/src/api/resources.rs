//! Declarative configuration resources (aether-kit `ResourceDef`): sites,
//! sensors, zones, device groups, classification rules, vendor
//! principals, remote access targets, assertions, saved views, threat
//! indicators, investigations, settings and rollouts (ZTE-IOT sections 3,
//! 21, 67, 70–75, 85–88, 104–105, 131; Volume 2 "Segmentation Policy",
//! "Device Inventory"). Every resource gets schema-validated create,
//! `If-Match` updates, dependency-checked soft delete, cursor pagination,
//! filters, search, audit and outbox events from the kit.

use crate::state::{CREATE, DELETE, READ, UPDATE};
use aether_kit::resource::{dep, f, fixed, r, req, Field, Kind, Mode, ResourceDef, ScopeDim};
use aether_kit::FieldError;
use iot_core::segmentation::GroupMatch;
use serde_json::{json, Map, Value};

fn fe(field: &str, code: &str, msg: impl Into<String>) -> FieldError {
    FieldError { field: field.into(), code: code.into(), message: msg.into() }
}

const LIST: Option<&str> = Some("iot");

macro_rules! def {
    ($n:ident, $name:expr, $table:expr, $entity:expr, $fields:expr, refs: $refs:expr, deps: $deps:expr, filters: $filters:expr, search: $search:expr, sorts: $sorts:expr, validate: $v:expr) => {
        pub static $n: ResourceDef = ResourceDef {
            name: $name,
            table: $table,
            entity: $entity,
            fields: $fields,
            refs: $refs,
            dependents: $deps,
            filters: $filters,
            search: $search,
            sorts: $sorts,
            hidden: &[],
            read: READ,
            create: CREATE,
            update: UPDATE,
            delete: Some(DELETE),
            scope: ScopeDim::None,
            entitlement: LIST,
            validate: $v,
        };
    };
}

const SITE_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    f("description", Kind::Text(2000)),
    f("region", Kind::Text(64)),
    f("address", Kind::Text(500)),
    f("timezone", Kind::Text(64)),
    f("criticality", Kind::Int(1, 5)),
    f("contact", Kind::Text(320)),
    f("tags", Kind::TextList(64)),
    f("branch_site_id", Kind::Text(64)),
    f("data_region", Kind::Text(64)),
];
def!(SITES, "sites", "sites", "site", SITE_FIELDS, refs: &[], deps: &[dep("sensors", "site_id", false, "sensors"), dep("zones", "site_id", false, "zones")],
    filters: &["region", "criticality"], search: &["name", "description", "address"], sorts: &["name", "criticality", "created_at"], validate: None);

fn validate_sensor(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    if let Some(c) = o.get("capture") {
        if !c.is_object() {
            return Err(vec![fe("capture", "invalid", "an object: {\"interfaces\": [...], \"tzsp\": bool, \"spool\": bool, \"filters\": [...]}")]);
        }
    }
    if let Some(n) = o.get("node_id").and_then(|v| v.as_str()) {
        if uuid::Uuid::parse_str(n).is_err() {
            return Err(vec![fe("node_id", "invalid", "the platform node id (UUID)")]);
        }
    }
    Ok(())
}

const SENSOR_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    req("site_id", Kind::Uuid),
    f("kind", Kind::Enum(&["edge_appliance", "span_port", "tap", "virtual", "branch_edge"])),
    f("node_id", Kind::Text(64)),
    f("description", Kind::Text(2000)),
    f("capture", Kind::Json),
    f("enforcement", Kind::Bool),
];
def!(SENSORS, "sensors", "sensors", "sensor", SENSOR_FIELDS, refs: &[r("site_id", "sites")], deps: &[],
    filters: &["site_id", "kind", "status"], search: &["name", "description"], sorts: &["name", "last_seen_at", "created_at"], validate: Some(validate_sensor));

fn validate_zone(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    if let Some(k) = o.get("key").and_then(|v| v.as_str()) {
        if k == iot_core::segmentation::QUARANTINE_GROUP && o.get("mode").and_then(|m| m.as_str()) == Some("observe") {
            return Err(vec![fe("mode", "invalid", "the quarantine zone must simulate or enforce")]);
        }
    }
    Ok(())
}

const ZONE_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    fixed("key", Kind::Key(64)),
    f("description", Kind::Text(2000)),
    f("security_level", Kind::Int(1, 4)),
    f("mode", Kind::Enum(&["observe", "simulate", "enforce"])),
    f("safety_critical", Kind::Bool),
    f("site_id", Kind::Uuid),
];
def!(ZONES, "zones", "zones", "zone", ZONE_FIELDS, refs: &[r("site_id", "sites")], deps: &[dep("device_groups", "zone_id", false, "device groups")],
    filters: &["mode", "security_level", "site_id", "safety_critical"], search: &["name", "key"], sorts: &["name", "security_level"], validate: Some(validate_zone));

fn validate_group(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    let mut errs = vec![];
    if let Some(m) = o.get("match") {
        match serde_json::from_value::<GroupMatch>(m.clone()) {
            Ok(g) => {
                for t in &g.device_types {
                    if !iot_core::taxonomy::is_known(t) {
                        errs.push(fe("match.device_types", "unknown_device_type", t.clone()));
                    }
                }
                for c in &g.categories {
                    if !iot_core::taxonomy::category_keys().contains(&c.as_str()) {
                        errs.push(fe("match.categories", "unknown_category", c.clone()));
                    }
                }
                for l in &g.risk_levels {
                    if !iot_core::policy::RISK_LEVELS.contains(&l.as_str()) {
                        errs.push(fe("match.risk_levels", "invalid", l.clone()));
                    }
                }
                o.insert("match".into(), serde_json::to_value(&g).unwrap_or(json!({})));
            }
            Err(e) => errs.push(fe("match", "invalid", e.to_string())),
        }
    }
    if let Some(c) = o.get("min_confidence").and_then(|v| v.as_f64()) {
        if !(0.0..=1.0).contains(&c) {
            errs.push(fe("min_confidence", "out_of_range", "0..1"));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

const GROUP_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    fixed("key", Kind::Key(64)),
    f("description", Kind::Text(2000)),
    f("priority", Kind::Int(-1000, 1000)),
    f("match", Kind::Json),
    f("zone_id", Kind::Uuid),
    f("privileged", Kind::Bool),
    f("min_confidence", Kind::Num(0.0, 1.0)),
];
def!(DEVICE_GROUPS, "device-groups", "device_groups", "device_group", GROUP_FIELDS, refs: &[r("zone_id", "zones")],
    deps: &[dep("vendor_principals", "allowed_group_ids", true, "vendor principals"), dep("exceptions", "source_group_id", false, "exceptions"), dep("exceptions", "destination_group_id", false, "exceptions")],
    filters: &["zone_id", "privileged"], search: &["name", "key", "description"], sorts: &["name", "priority"], validate: Some(validate_group));

fn validate_rule(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    let rule = iot_core::classify::Rule {
        id: String::new(),
        source: o.get("source").and_then(|v| v.as_str()).unwrap_or("").into(),
        field: o.get("field").and_then(|v| v.as_str()).unwrap_or("").into(),
        kind: serde_json::from_value(o.get("match").cloned().unwrap_or(json!("exact"))).unwrap_or(iot_core::classify::Match::Exact),
        pattern: o.get("pattern").and_then(|v| v.as_str()).unwrap_or("").into(),
        device_type: o.get("device_type").and_then(|v| v.as_str()).map(String::from),
        vendor: o.get("vendor").and_then(|v| v.as_str()).map(String::from),
        model: o.get("model").and_then(|v| v.as_str()).map(String::from),
        os: o.get("os").and_then(|v| v.as_str()).map(String::from),
        weight: o.get("weight").and_then(|v| v.as_f64()).unwrap_or(0.8),
        origin: "custom".into(),
    };
    rule.validate().map_err(|c| vec![fe("pattern", c, "invalid classification rule")])
}

const RULE_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    req("source", Kind::Enum(iot_core::classify::SOURCES)),
    req("field", Kind::Text(64)),
    f("match", Kind::Enum(&["exact", "prefix", "suffix", "contains", "glob"])),
    req("pattern", Kind::Text(256)),
    f("device_type", Kind::Text(64)),
    f("vendor", Kind::Text(128)),
    f("model", Kind::Text(128)),
    f("os", Kind::Text(64)),
    f("weight", Kind::Num(0.05, 0.99)),
    f("enabled", Kind::Bool),
    f("origin", Kind::Enum(&["custom", "learned"])),
];
def!(CLASSIFICATION_RULES, "classification-rules", "classification_rules", "classification_rule", RULE_FIELDS, refs: &[], deps: &[],
    filters: &["source", "enabled", "origin", "device_type"], search: &["name", "pattern"], sorts: &["name", "weight", "created_at"], validate: Some(validate_rule));

fn validate_vendor(o: &mut Map<String, Value>, mode: &Mode) -> Result<(), Vec<FieldError>> {
    if let Some(e) = o.get("expires_at").and_then(|v| v.as_str()) {
        let t: chrono::DateTime<chrono::Utc> = e.parse().map_err(|_| vec![fe("expires_at", "invalid", "RFC 3339")])?;
        if matches!(mode, Mode::Create) && t <= chrono::Utc::now() {
            return Err(vec![fe("expires_at", "in_past", "must be in the future")]);
        }
        if t > chrono::Utc::now() + chrono::Duration::days(366) {
            return Err(vec![fe("expires_at", "too_far", "vendor access expires within a year")]);
        }
    }
    if let Some(e) = o.get("email").and_then(|v| v.as_str()) {
        o.insert("email".into(), json!(e.trim().to_ascii_lowercase()));
    }
    Ok(())
}

const VENDOR_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    req("company", Kind::Text(200)),
    req("email", Kind::Email),
    f("phone", Kind::Text(64)),
    req("expires_at", Kind::Timestamp),
    f("enabled", Kind::Bool),
    f("allowed_group_ids", Kind::UuidList),
    f("max_session_minutes", Kind::Int(5, 720)),
    f("require_mfa", Kind::Bool),
    f("notes", Kind::Text(4000)),
];
def!(VENDOR_PRINCIPALS, "vendor-principals", "vendor_principals", "vendor_principal", VENDOR_FIELDS, refs: &[r("allowed_group_ids", "device_groups")], deps: &[],
    filters: &["company", "enabled"], search: &["name", "company", "email"], sorts: &["name", "expires_at"], validate: Some(validate_vendor));

fn validate_target(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    if let Some(p) = o.get("protocols").and_then(|v| v.as_array()) {
        for x in p {
            if !x.as_str().map(|s| iot_core::policy::REMOTE_PROTOCOLS.contains(&s)).unwrap_or(false) {
                return Err(vec![fe("protocols", "invalid", format!("one of {}", iot_core::policy::REMOTE_PROTOCOLS.join(", ")))]);
            }
        }
    }
    Ok(())
}

const TARGET_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    f("asset_id", Kind::Uuid),
    f("console_id", Kind::Text(64)),
    f("protocols", Kind::TextList(8)),
    f("host", Kind::Text(253)),
    f("port", Kind::Int(1, 65535)),
    f("require_approval", Kind::Bool),
    f("description", Kind::Text(2000)),
];
def!(REMOTE_TARGETS, "remote-targets", "remote_targets", "remote_target", TARGET_FIELDS, refs: &[], deps: &[],
    filters: &["asset_id", "require_approval"], search: &["name", "host"], sorts: &["name"], validate: Some(validate_target));

fn validate_assertion(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    if let Some(e) = o.get("expression").and_then(|v| v.as_str()) {
        iot_core::assertions::parse(e).map_err(|m| vec![fe("expression", "invalid_expression", m)])?;
    }
    Ok(())
}

const ASSERTION_FIELDS: &[Field] =
    &[req("name", Kind::Text(200)), req("expression", Kind::Text(2000)), f("severity", Kind::Int(1, 10)), f("enabled", Kind::Bool), f("description", Kind::Text(2000))];
def!(ASSERTIONS, "assertions", "assertions", "assertion", ASSERTION_FIELDS, refs: &[], deps: &[],
    filters: &["enabled", "severity"], search: &["name", "expression"], sorts: &["name", "violations", "last_run_at"], validate: Some(validate_assertion));

fn validate_view(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    validate_assertion(&mut Map::from_iter(o.get("query").map(|q| ("expression".to_string(), q.clone()))), &Mode::Create)
        .map_err(|_| vec![fe("query", "invalid_expression", "query must be a valid inventory expression")])
}

const VIEW_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    req("resource", Kind::Enum(&["assets", "anomalies", "findings", "alerts", "remote-sessions"])),
    f("query", Kind::Text(2000)),
    f("filters", Kind::Json),
    f("columns", Kind::TextList(64)),
    f("shared", Kind::Bool),
];
def!(SAVED_VIEWS, "saved-views", "saved_views", "saved_view", VIEW_FIELDS, refs: &[], deps: &[],
    filters: &["resource", "shared"], search: &["name"], sorts: &["name"], validate: Some(validate_view));

fn validate_indicator(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    if let (Some(i), Some(k)) = (o.get("indicator").and_then(|v| v.as_str()), o.get("kind").and_then(|v| v.as_str())) {
        let ok = match k {
            "ip" => i.parse::<std::net::IpAddr>().is_ok(),
            "domain" => i.contains('.') && !i.contains(' '),
            _ => true,
        };
        if !ok {
            return Err(vec![fe("indicator", "invalid", format!("not a valid {k}"))]);
        }
        o.insert("indicator".into(), json!(i.trim().to_ascii_lowercase()));
    }
    Ok(())
}

const INDICATOR_FIELDS: &[Field] = &[
    req("indicator", Kind::Text(253)),
    f("kind", Kind::Enum(&["ip", "domain"])),
    f("source", Kind::Text(100)),
    f("severity", Kind::Int(1, 10)),
    f("expires_at", Kind::Timestamp),
    f("description", Kind::Text(2000)),
];
def!(THREAT_INDICATORS, "threat-indicators", "threat_indicators", "threat_indicator", INDICATOR_FIELDS, refs: &[], deps: &[],
    filters: &["kind", "source"], search: &["indicator", "description"], sorts: &["indicator", "severity", "created_at"], validate: Some(validate_indicator));

const INVESTIGATION_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    f("description", Kind::Text(4000)),
    f("status", Kind::Enum(&["open", "in_progress", "closed"])),
    f("severity", Kind::Int(1, 10)),
    f("asset_ids", Kind::UuidList),
    f("anomaly_ids", Kind::UuidList),
    f("assignee", Kind::Text(320)),
    f("notes", Kind::Text(20000)),
];
def!(INVESTIGATIONS, "investigations", "investigations", "investigation", INVESTIGATION_FIELDS, refs: &[], deps: &[],
    filters: &["status", "severity", "assignee"], search: &["name", "description"], sorts: &["name", "severity", "created_at"], validate: None);

pub const SETTINGS_NAMES: &[&str] = &["active_queries", "risk_tuning", "remote_access", "learning", "retention", "health_thresholds", "classification"];

fn validate_settings(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    let name = o.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let v = o.get("value").cloned().unwrap_or(json!({}));
    let bad = |m: String| Err(vec![fe("value", "invalid", m)]);
    match name {
        "active_queries" => serde_json::from_value::<iot_core::activeq::Settings>(v).map(|_| ()).or_else(|e| bad(e.to_string())),
        "risk_tuning" => match serde_json::from_value::<iot_core::risk::Tuning>(v) {
            Ok(t) => t.validate().or_else(bad),
            Err(e) => bad(e.to_string()),
        },
        "remote_access" => serde_json::from_value::<iot_core::remote::Limits>(v).map(|_| ()).or_else(|e| bad(e.to_string())),
        "learning" => serde_json::from_value::<iot_core::baseline::LearningPolicy>(v).map(|_| ()).or_else(|e| bad(e.to_string())),
        "health_thresholds" => serde_json::from_value::<iot_core::failure::Thresholds>(v).map(|_| ()).or_else(|e| bad(e.to_string())),
        "retention" | "classification" => {
            if v.is_object() {
                Ok(())
            } else {
                bad("an object".into())
            }
        }
        _ => Err(vec![fe("name", "unknown_setting", SETTINGS_NAMES.join(", "))]),
    }
}

const SETTINGS_FIELDS: &[Field] = &[fixed("name", Kind::Enum(SETTINGS_NAMES)), req("value", Kind::Json)];
def!(SETTINGS, "settings", "settings", "settings", SETTINGS_FIELDS, refs: &[], deps: &[], filters: &["name"], search: &["name"], sorts: &["name"], validate: Some(validate_settings));

fn validate_rollout(o: &mut Map<String, Value>, _: &Mode) -> Result<(), Vec<FieldError>> {
    if let Some(st) = o.get("stages") {
        let ok = st.as_array().map(|a| !a.is_empty() && a.len() <= 10 && a.iter().all(|s| s["zone_ids"].is_array())).unwrap_or(false);
        if !ok {
            return Err(vec![fe("stages", "invalid", "1..10 stages of {\"zone_ids\": [...], \"min_hours\": n}")]);
        }
    }
    Ok(())
}

const ROLLOUT_FIELDS: &[Field] =
    &[req("name", Kind::Text(200)), req("zone_ids", Kind::UuidList), fixed("target_mode", Kind::Enum(&["observe", "simulate", "enforce"])), req("stages", Kind::Json)];
def!(ROLLOUTS, "rollouts", "rollouts", "rollout", ROLLOUT_FIELDS, refs: &[r("zone_ids", "zones")], deps: &[],
    filters: &["state", "target_mode"], search: &["name"], sorts: &["name", "created_at"], validate: Some(validate_rollout));

/// Exceptions are created through `POST /api/v1/exceptions` (approval
/// workflow, api/segmentation.rs); the definition serves reads, updates
/// of the description and the console metadata.
/// Optional on create, immutable afterwards.
const fn once(name: &'static str, kind: Kind) -> Field {
    Field { name, kind, required: false, patchable: false }
}

const EXCEPTION_FIELDS: &[Field] = &[
    req("name", Kind::Text(200)),
    req("justification", Kind::Text(4000)),
    once("source_asset_id", Kind::Uuid),
    once("destination_asset_id", Kind::Uuid),
    once("source_group_id", Kind::Uuid),
    once("destination_group_id", Kind::Uuid),
    once("protocol", Kind::Text(32)),
    once("port", Kind::Int(1, 65535)),
    once("max_op", Kind::Enum(iot_core::protocols::OP_CLASSES)),
    req("starts_at", Kind::Timestamp),
    req("expires_at", Kind::Timestamp),
];
def!(EXCEPTIONS, "exceptions", "exceptions", "exception", EXCEPTION_FIELDS, refs: &[r("source_group_id", "device_groups"), r("destination_group_id", "device_groups")], deps: &[],
    filters: &["state", "source_asset_id", "destination_asset_id"], search: &["name", "justification"], sorts: &["name", "expires_at", "created_at"], validate: None);

pub static ALL: &[&ResourceDef] = &[
    &SITES,
    &SENSORS,
    &ZONES,
    &DEVICE_GROUPS,
    &CLASSIFICATION_RULES,
    &VENDOR_PRINCIPALS,
    &REMOTE_TARGETS,
    &EXCEPTIONS,
    &ASSERTIONS,
    &SAVED_VIEWS,
    &THREAT_INDICATORS,
    &INVESTIGATIONS,
    &SETTINGS,
    &ROLLOUTS,
];

/// Resources whose creation goes through a custom handler.
pub const CUSTOM_CREATE: &[&str] = &["exceptions"];

#[cfg(test)]
mod tests {
    use super::*;
    use aether_kit::resource::validate_body;

    #[test]
    fn validators() {
        let ok = validate_body(&DEVICE_GROUPS, &json!({"name": "PLCs", "key": "plcs", "match": {"device_types": ["plc"]}}), &Mode::Create).unwrap();
        let mut o = ok.clone();
        assert!(validate_group(&mut o, &Mode::Create).is_ok());
        let mut bad = Map::new();
        bad.insert("match".into(), json!({"device_types": ["toaster"]}));
        assert!(validate_group(&mut bad, &Mode::Create).is_err());
        let mut rule: Map<String, Value> =
            serde_json::from_value(json!({"source": "dns", "field": "query", "match": "suffix", "pattern": "x.example", "device_type": "ip_camera", "weight": 0.8})).unwrap();
        assert!(validate_rule(&mut rule, &Mode::Create).is_ok());
        rule.insert("device_type".into(), json!("toaster"));
        assert!(validate_rule(&mut rule, &Mode::Create).is_err());
        let mut s: Map<String, Value> = serde_json::from_value(json!({"name": "risk_tuning", "value": {"weights": {"vulnerability": 0.5}}})).unwrap();
        assert!(validate_settings(&mut s, &Mode::Create).is_ok());
        s.insert("value".into(), json!({"weights": {"nope": 1}}));
        assert!(validate_settings(&mut s, &Mode::Create).is_err());
        let mut a: Map<String, Value> = serde_json::from_value(json!({"expression": "category == "})).unwrap();
        assert!(validate_assertion(&mut a, &Mode::Create).is_err());
        let mut ti: Map<String, Value> = serde_json::from_value(json!({"indicator": "Not An IP", "kind": "ip"})).unwrap();
        assert!(validate_indicator(&mut ti, &Mode::Create).is_err());
    }
}
