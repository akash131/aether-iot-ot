//! Governance and lifecycle: tenant classification rules and dynamic
//! re-assignment, staged zone-mode rollouts and configuration rollback,
//! asset merge/split, saved views, settings validation, reports and
//! dashboards, graph dependencies, retention housekeeping and the worker
//! cycle.

mod common;

use common::*;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn tenant_rules_reclassify_and_reassign_dynamically() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let zone = h.post("/api/v1/zones", &tok, json!({ "name": "HMIs", "key": "hmis", "security_level": 2, "mode": "simulate" })).await;
    let g = h.post("/api/v1/device-groups", &tok, json!({ "name": "HMIs", "key": "hmis", "priority": 50, "match": { "device_types": ["hmi"] }, "zone_id": zone["id"] })).await;
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(60)).await;
    let hmi = h.asset_by_ip(&tok, "10.60.0.20").await;
    assert_ne!(hmi["device_type"], "hmi", "{hmi}");
    // Custom rule: this vendor prefix is an HMI at this customer.
    h.post(
        "/api/v1/classification-rules",
        &tok,
        json!({ "name": "Site HMIs", "source": "oui", "field": "vendor", "match": "exact", "pattern": "siemens", "device_type": "hmi", "vendor": "Siemens", "weight": 0.95 }),
    )
    .await;
    let n = iot_service::workers::sweep(&h.state, t).await.unwrap();
    assert!(n >= 1, "configuration change re-evaluates the inventory");
    let hmi = h.asset_by_ip(&tok, "10.60.0.20").await;
    assert_eq!(hmi["device_type"], "hmi", "{hmi}");
    assert!(hmi["group_ids"].to_string().contains(g["id"].as_str().unwrap()), "dynamic re-assignment: {hmi}");
    let ev = h.get(&format!("/api/v1/assets/{}/classification", hmi["id"].as_str().unwrap()), &tok).await;
    assert!(ev.to_string().contains("custom"), "tenant rule visible in the explanation: {ev}");
    // Invalid rules are refused.
    let (s, _, _) = h
        .call(
            Method::POST,
            "/api/v1/classification-rules",
            Some(&tok),
            Some(json!({ "name": "bad", "source": "dhcp", "field": "hostname", "match": "glob", "pattern": "", "device_type": "hmi" })),
            &[],
        )
        .await;
    assert_eq!(s, 422);
}

#[tokio::test]
async fn staged_rollouts_and_configuration_rollback() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let z1 = h.post("/api/v1/zones", &tok, json!({ "name": "Line 1", "key": "line1", "mode": "observe" })).await;
    let z2 = h.post("/api/v1/zones", &tok, json!({ "name": "Line 2", "key": "line2", "mode": "observe" })).await;
    let (_, _, _, node) = h.site_and_sensor(t).await;
    // A snapshot fetch records revision 1 (observe everywhere).
    let (s, _, _) = h.call(Method::GET, "/api/v1/node/snapshot", Some(&node), None, &[]).await;
    assert_eq!(s, 200);
    let ro = h
        .post(
            "/api/v1/rollouts",
            &tok,
            json!({ "name": "Enforce lines", "zone_ids": [z1["id"], z2["id"]], "target_mode": "enforce", "stages": [{ "zone_ids": [z1["id"]] }, { "zone_ids": [z2["id"]] }] }),
        )
        .await;
    let rid = ro["id"].as_str().unwrap();
    h.post(&format!("/api/v1/rollouts/{rid}/start"), &tok, json!({})).await;
    let mode = |v: serde_json::Value| v["data"]["mode"].as_str().unwrap().to_string();
    assert_eq!(mode(h.get(&format!("/api/v1/zones/{}", z1["id"].as_str().unwrap()), &tok).await), "enforce");
    assert_eq!(mode(h.get(&format!("/api/v1/zones/{}", z2["id"].as_str().unwrap()), &tok).await), "observe");
    h.post(&format!("/api/v1/rollouts/{rid}/advance"), &tok, json!({})).await;
    assert_eq!(mode(h.get(&format!("/api/v1/zones/{}", z2["id"].as_str().unwrap()), &tok).await), "enforce");
    let (s, _, _) = h.call(Method::POST, &format!("/api/v1/rollouts/{rid}/advance"), Some(&tok), Some(json!({})), &[]).await;
    assert_eq!(s, 409, "completed rollout cannot advance");
    h.post(&format!("/api/v1/rollouts/{rid}/rollback"), &tok, json!({})).await;
    assert_eq!(mode(h.get(&format!("/api/v1/zones/{}", z1["id"].as_str().unwrap()), &tok).await), "observe");
    // Configuration revisions: roll back to revision 1.
    let ver = h.get(&format!("/api/v1/zones/{}", z1["id"].as_str().unwrap()), &tok).await["data"]["version"].as_i64().unwrap();
    h.patch(&format!("/api/v1/zones/{}", z1["id"].as_str().unwrap()), &tok, ver, json!({ "mode": "enforce" })).await;
    let revs = h.get("/api/v1/config-revisions", &tok).await;
    let first = revs["data"].as_array().unwrap().iter().map(|r| r["revision"].as_i64().unwrap()).min().unwrap();
    let rb = h.post(&format!("/api/v1/config-revisions/{first}/rollback"), &tok, json!({})).await;
    assert!(rb["zones"].as_u64().unwrap() >= 1, "{rb}");
    assert_eq!(mode(h.get(&format!("/api/v1/zones/{}", z1["id"].as_str().unwrap()), &tok).await), "observe");
}

#[tokio::test]
async fn merge_split_views_settings_reports_and_dashboards() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(61)).await;
    let imp = h
        .post("/api/v1/assets/import", &tok, json!({ "assets": [{ "mac": "00:80:f4:3d:00:99", "hostname": "plc-spare", "device_type": "plc", "vendor": "Schneider Electric" }] }))
        .await;
    let _ = imp;
    let plc = h.asset_by_ip(&tok, "10.61.0.10").await;
    let spare = h.get("/api/v1/assets?mac=00:80:f4:3d:00:99", &tok).await["data"][0].clone();
    let m = h.post("/api/v1/assets/merge", &tok, json!({ "into": plc["id"], "from": [spare["id"]], "reason": "same chassis" })).await;
    assert!(m.to_string().contains(plc["id"].as_str().unwrap()), "{m}");
    let (s, _, _) = h.call(Method::GET, &format!("/api/v1/assets/{}", spare["id"].as_str().unwrap()), Some(&tok), None, &[]).await;
    assert!(s == 404 || s == 200);
    let ids = h.get(&format!("/api/v1/assets/{}/identities", plc["id"].as_str().unwrap()), &tok).await;
    assert!(ids.to_string().contains("plc-spare"), "{ids}");
    let sp = h
        .post(
            &format!("/api/v1/assets/{}/split", plc["id"].as_str().unwrap()),
            &tok,
            json!({ "keys": [{ "key_type": "hostname", "value": "plc-spare" }], "reason": "two devices" }),
        )
        .await;
    assert!(sp.to_string().contains("id"), "{sp}");
    // Saved views and settings validation.
    h.post("/api/v1/saved-views", &tok, json!({ "name": "High-risk controllers", "resource": "assets", "query": "category == \"industrial_control\" and risk_score >= 50" })).await;
    let (s, _, _) = h.call(Method::POST, "/api/v1/saved-views", Some(&tok), Some(json!({ "name": "bad", "resource": "assets", "query": "risk_score >>> 1" })), &[]).await;
    assert_eq!(s, 422);
    let (s, _, _) = h.call(Method::POST, "/api/v1/settings", Some(&tok), Some(json!({ "name": "risk_tuning", "value": { "weights": { "exposure": 9 } } })), &[]).await;
    assert_eq!(s, 422);
    h.post("/api/v1/settings", &tok, json!({ "name": "remote_access", "value": { "max_window_minutes": 120, "max_session_minutes": 60, "idle_timeout_minutes": 10, "max_advance_days": 7, "require_ticket": true } })).await;
    // Reports (JSON and CSV) and dashboards.
    for k in ["inventory", "risk", "vulnerabilities", "anomalies", "remote_access", "segmentation"] {
        h.get(&format!("/api/v1/reports/{k}"), &tok).await;
    }
    let (s, csv, _) = h.call(Method::GET, "/api/v1/reports/inventory?format=csv", Some(&tok), None, &[]).await;
    assert_eq!(s, 200);
    assert!(csv.as_str().unwrap_or_default().contains("10.61.0.10"));
    for d in ["overview", "risk", "ot-activity", "remote-access"] {
        let v = h.get(&format!("/api/v1/dashboards/{d}"), &tok).await;
        assert!(v["data"].is_object(), "{d}: {v}");
    }
    let g = h.get(&format!("/api/v1/graph/dependencies?asset_id={}", plc["id"].as_str().unwrap()), &tok).await;
    assert!(g["data"].to_string().contains("10.61.0.20") || g["data"].to_string().contains("dependents"), "{g}");
    let ex = h.get(&format!("/api/v1/assets/{}/peers", plc["id"].as_str().unwrap()), &tok).await;
    assert!(!ex["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn worker_cycle_and_retention() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(62)).await;
    // Old history beyond retention is purged; append-only tables accept purges only under the retention flag.
    let mut tx = aether_kit::db::tenant_tx(&h.pool, t).await.unwrap();
    let r = sqlx::query("DELETE FROM asset_changes").execute(&mut *tx).await;
    assert!(r.is_err(), "asset changes are append-only");
    drop(tx);
    let mut tx = aether_kit::db::tenant_tx(&h.pool, t).await.unwrap();
    sqlx::query("UPDATE observations SET received_at = now() - interval '30 days'").execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let n = iot_service::workers::housekeeping(&h.state, t).await.unwrap();
    assert!(n >= 3, "{n}");
    assert_eq!(h.count("observations", t).await, 0);
    // The per-tenant worker steps without a platform are no-ops that never fail
    // (the shared test database holds many tenants, so the full cycle is not run here).
    iot_service::workers::supervise_remote(&h.state, t).await.unwrap();
    iot_service::workers::sync_approvals(&h.state, t).await.unwrap();
    iot_service::workers::sweep(&h.state, t).await.unwrap();
    iot_service::workers::pull_branch(&h.state, t).await.unwrap();
    iot_service::workers::push_firewall(&h.state, t).await.unwrap();
    assert_eq!(iot_service::workers::ship_logs(&h.state).await.unwrap(), 0, "nothing is shipped without platform credentials");
    let st = h.get("/api/v1/status", &tok).await;
    assert!(st["data"].is_object(), "{st}");
    let diag = h.get("/api/v1/diagnostics", &tok).await;
    assert!(diag["data"].is_object(), "{diag}");
}
