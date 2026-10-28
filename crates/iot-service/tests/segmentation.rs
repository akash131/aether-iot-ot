//! Segmentation: zones and device groups, automatic assignment, read vs
//! write decisions with draft and recommended rule sets, observe/simulate/
//! enforce modes, safety-sensitive protection, temporary exceptions with
//! approval, simulation over observed flows, edge snapshots and policy
//! hooks.

mod common;

use aether_core::policy::{Condition, Op, Rule, RuleSet};
use common::*;
use serde_json::{json, Value};
use uuid::Uuid;

fn ruleset(rules: Vec<(&str, Condition, &str)>) -> Value {
    let rules = rules
        .into_iter()
        .enumerate()
        .map(|(i, (name, condition, action))| Rule {
            id: iot_core::stable_uuid(name),
            name: name.into(),
            description: String::new(),
            order: i as i32 + 1,
            enabled: true,
            condition,
            action: action.into(),
            params: Default::default(),
            schedule: Default::default(),
            emergency: false,
            labels: vec![],
        })
        .collect();
    serde_json::to_value(RuleSet { policy_type: "iot.segmentation".into(), default_action: "allow".into(), default_params: Default::default(), rules }).unwrap()
}

async fn setup(h: &Harness, t: Uuid, mode: &str) -> (String, String, String) {
    let tok = h.admin(t);
    let ot = h.post("/api/v1/zones", &tok, json!({ "name": "Cell 1 control", "key": "cell1", "security_level": 2, "mode": mode, "safety_critical": false })).await;
    let plcs = h
        .post(
            "/api/v1/device-groups",
            &tok,
            json!({ "name": "PLCs", "key": "plcs", "priority": 100, "match": { "device_types": ["plc"] }, "zone_id": ot["id"], "privileged": false, "min_confidence": 0.6 }),
        )
        .await;
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(43)).await;
    (ot["id"].as_str().unwrap().into(), plcs["id"].as_str().unwrap().into(), node)
}

#[tokio::test]
async fn read_and_write_operations_are_decided_differently() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (zone, plcs, _) = setup(&h, t, "enforce").await;
    let plc = h.asset_by_ip(&tok, "10.43.0.10").await;
    assert!(plc["group_ids"].as_array().unwrap().iter().any(|g| g == &json!(plcs)), "PLC assigned to the PLC group: {plc}");
    assert_eq!(plc["zone_id"], json!(zone));
    let rs = ruleset(vec![(
        "Block writes to PLCs",
        Condition::All(vec![
            Condition::pred("destination.device_group", Op::In, vec![json!(plcs)]),
            Condition::pred("network.operation_class", Op::In, vec![json!("write"), json!("control"), json!("program"), json!("firmware")]),
        ]),
        "block",
    )]);
    let decide =
        |op: &'static str| json!({ "source_ip": "10.43.0.30", "destination_ip": "10.43.0.10", "protocol": "modbus", "operation_class": op, "port": 502, "ruleset": rs.clone() });
    let r = h.post("/api/v1/segmentation/decide", &tok, decide("read")).await;
    assert_eq!(r["verdict"]["enforced"], "allow", "{r}");
    let w = h.post("/api/v1/segmentation/decide", &tok, decide("write")).await;
    assert_eq!(w["verdict"]["policy_action"], "block", "{w}");
    // The PLC is safety sensitive, but the block comes from an explicit rule.
    assert_eq!(w["verdict"]["enforced"], "block", "{w}");
    assert_eq!(w["verdict"]["rule_name"], "Block writes to PLCs");
    // Default (fail-secure) blocks never cut a safety-sensitive destination.
    let deny_all = json!({ "policy_type": "iot.segmentation", "default_action": "block", "default_params": {}, "rules": [] });
    let d = h.post("/api/v1/segmentation/decide", &tok, json!({ "source_ip": "10.43.0.30", "destination_ip": "10.43.0.10", "operation_class": "read", "ruleset": deny_all })).await;
    assert_eq!(d["verdict"]["enforced"], "allow", "{d}");
    // Simulation over the observed flows: the observed write would be blocked.
    let sim = h.post("/api/v1/segmentation/simulate", &tok, json!({ "hours": 1, "ruleset": rs })).await;
    assert!(sim["simulation"].to_string().contains("block"), "{sim}");
    // Invalid draft rule sets are 422 problems, not 500.
    let (s, v, _) = h
        .call(
            Method::POST,
            "/api/v1/segmentation/decide",
            Some(&tok),
            Some(json!({ "ruleset": { "policy_type": "iot.segmentation", "default_action": "explode", "default_params": {}, "rules": [] } })),
            &[],
        )
        .await;
    assert!(s == 422 || s == 400, "{s} {v}");
}

#[tokio::test]
async fn observe_mode_never_blocks_and_recommendations_come_from_baselines() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, plcs, _) = setup(&h, t, "observe").await;
    let rs = ruleset(vec![("Block all to PLCs", Condition::pred("destination.device_group", Op::In, vec![json!(plcs)]), "block")]);
    let w = h.post("/api/v1/segmentation/decide", &tok, json!({ "source_ip": "10.43.0.30", "destination_ip": "10.43.0.10", "operation_class": "write", "ruleset": rs })).await;
    assert_eq!(w["verdict"]["policy_action"], "block");
    assert_eq!(w["verdict"]["enforced"], "allow", "{w}");
    let r = h.get(&format!("/api/v1/segmentation/recommendations?group_id={plcs}"), &tok).await;
    assert_eq!(r["data"]["ruleset"]["policy_type"], "iot.segmentation", "{r}");
    let c = h.get("/api/v1/segmentation/conduits", &tok).await;
    assert!(c["data"].to_string().contains("modbus"), "{c}");
}

#[tokio::test]
async fn temporary_exceptions_need_approval_and_expire() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, plcs, _) = setup(&h, t, "enforce").await;
    let ews = h.asset_by_ip(&tok, "10.43.0.30").await;
    let now = chrono::Utc::now();
    let body = json!({ "source_asset_id": ews["id"], "destination_group_id": plcs, "protocol": "modbus", "port": 502, "max_op": "write",
        "starts_at": now, "expires_at": now + chrono::Duration::hours(2), "name": "Commissioning writes", "justification": "commissioning" });
    let (s, v, _) = h.call(Method::POST, "/api/v1/exceptions", Some(&tok), Some(body), &[]).await;
    assert_eq!(s, 201, "{v}");
    let id = v["data"]["exception"]["id"].as_str().unwrap().to_string();
    assert_eq!(v["data"]["exception"]["state"], "pending_approval", "{v}");
    // The requester cannot approve their own exception (separation of duties).
    let (s, _, _) = h.call(Method::POST, &format!("/api/v1/exceptions/{id}/approve"), Some(&tok), None, &[]).await;
    assert_eq!(s, 403);
    let approver = h.admin(t);
    h.post(&format!("/api/v1/exceptions/{id}/approve"), &approver, json!({})).await;
    let rs = ruleset(vec![("Block writes", Condition::pred("network.operation_class", Op::In, vec![json!("write")]), "block")]);
    let w = h
        .post(
            "/api/v1/segmentation/decide",
            &tok,
            json!({ "source_ip": "10.43.0.30", "destination_ip": "10.43.0.10", "protocol": "modbus", "operation_class": "write", "port": 502, "ruleset": rs.clone() }),
        )
        .await;
    assert_eq!(w["verdict"]["exception_id"], json!(id), "{w}");
    assert_eq!(w["verdict"]["enforced"], "allow");
    // Revoked: the rule applies again.
    h.post(&format!("/api/v1/exceptions/{id}/revoke"), &approver, json!({})).await;
    let w = h
        .post(
            "/api/v1/segmentation/decide",
            &tok,
            json!({ "source_ip": "10.43.0.30", "destination_ip": "10.43.0.10", "protocol": "modbus", "operation_class": "write", "port": 502, "ruleset": rs }),
        )
        .await;
    assert_eq!(w["verdict"]["enforced"], "block", "{w}");
    // Too long an exception is refused.
    let (s, _, _) = h
        .call(
            Method::POST,
            "/api/v1/exceptions",
            Some(&tok),
            Some(json!({ "source_asset_id": ews["id"], "destination_group_id": plcs, "starts_at": now, "expires_at": now + chrono::Duration::days(120), "name": "too long", "justification": "x" })),
            &[],
        )
        .await;
    assert_eq!(s, 422);
}

#[tokio::test]
async fn edge_snapshot_is_hashed_versioned_and_conditional() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, plcs, node) = setup(&h, t, "enforce").await;
    let (s, v, hd) = h.call(Method::GET, "/api/v1/node/snapshot", Some(&node), None, &[]).await;
    assert_eq!(s, 200, "{v}");
    let doc = &v["data"];
    assert!(iot_service::api::ingest::verify_snapshot(doc), "{doc}");
    assert!(doc["groups"].to_string().contains(&plcs));
    assert!(doc["devices"].as_array().unwrap().len() >= 3);
    let etag = hd["etag"].to_str().unwrap().to_string();
    let (s, _, _) = h.call(Method::GET, "/api/v1/node/snapshot", Some(&node), None, &[("if-none-match", &etag)]).await;
    assert_eq!(s, 304);
    // A tampered document fails verification.
    let mut bad = doc.clone();
    bad["devices"] = json!([]);
    assert!(!iot_service::api::ingest::verify_snapshot(&bad));
    // Revisions are recorded and can be listed.
    let r = h.get("/api/v1/config-revisions", &tok).await;
    assert!(!r["data"].as_array().unwrap().is_empty(), "{r}");
    // Platform policy hooks: unknown references are reported missing.
    let svc = h.token(t, aether_kit::ActorType::Service, &[], &["iot"]);
    let missing = Uuid::now_v7().to_string();
    let r = h.post("/api/v1/policy-hooks/references", &svc, json!({ "policy_type": "iot.segmentation", "ref_type": "iot.device_group", "ids": [plcs, missing] })).await;
    assert_eq!(r["missing"], json!([missing]), "{r}");
}
