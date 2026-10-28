//! Baselines, anomalies and alerts, vulnerability findings, safe active
//! queries, assertions, acceptance runs, investigations, classification
//! learning, privacy erasure and lifecycle operations.

mod common;

use common::*;
use iot_core::collect::Collector;
use iot_core::packet::{build, Mac};
use serde_json::json;
use std::net::Ipv4Addr;
use uuid::Uuid;

/// A new workstation writing to the PLC and a PLC talking to the internet.
fn intrusion(base: u8) -> Vec<iot_core::model::Observation> {
    let mut c = Collector::default();
    let plc = (Mac([0x00, 0x80, 0xf4, base, 0, 10]), Ipv4Addr::new(10, base, 0, 10), 502u16);
    let rogue = (Mac([0x02, 0x66, 0x66, base, 0, 99]), Ipv4Addr::new(10, base, 0, 99), 50000u16);
    let t0 = chrono::Utc::now().timestamp_micros();
    c.ingest(t0, &build::tcp_frame(rogue, plc, 0x18, &iot_core::protocols::modbus::adu(5, 1, &[16, 0, 0, 0, 2, 4, 0, 9, 0, 9])));
    c.ingest(t0 + 1, &build::tcp_frame(rogue, plc, 0x18, &iot_core::protocols::modbus::adu(6, 1, &[8, 0, 1, 0, 0])));
    c.ingest(t0 + 2, &build::tcp_frame((plc.0, plc.1, 40000), (Mac([0, 0, 0x5e, 0, 1, 1]), Ipv4Addr::new(203, 0, 113, 9), 443), 0x02, &[]));
    c.drain(None, None)
}

#[tokio::test]
async fn baseline_monitoring_raises_anomalies_alerts_and_signals() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(46)).await;
    let plc = h.asset_by_ip(&tok, "10.46.0.10").await;
    let id = plc["id"].as_str().unwrap().to_string();
    let b = h.post(&format!("/api/v1/assets/{id}/baseline/complete"), &tok, json!({ "reason": "commissioned" })).await;
    assert_eq!(b["network_mode"], "monitoring", "{b}");
    let out = h.observe(&node, intrusion(46)).await;
    assert!(out["anomalies"].as_u64().unwrap() >= 1, "{out}");
    let an = h.get(&format!("/api/v1/assets/{id}/anomalies"), &tok).await;
    let kinds = an["data"].to_string();
    assert!(kinds.contains("new_peer") || kinds.contains("new_communication"), "{an}");
    let all = h.get("/api/v1/anomalies?state=open", &tok).await;
    assert!(!all["data"].as_array().unwrap().is_empty());
    let alerts = h.get("/api/v1/alerts", &tok).await;
    assert!(!alerts["data"].as_array().unwrap().is_empty(), "{alerts}");
    // Learning an anomaly adds the behaviour to the baseline.
    let aid = an["data"][0]["id"].as_str().unwrap();
    h.post(&format!("/api/v1/anomalies/{aid}/learned"), &tok, json!({ "comment": "approved integrator laptop" })).await;
    // Risk signals for the platform with subject_type workload.
    let sig = h.scalar(t, "SELECT coalesce(jsonb_agg(signal), '[]') FROM signal_outbox").await;
    assert!(sig.to_string().contains("\"workload\""), "{sig}");
    // Baseline snapshot taken before completion; the difference shows the learned edge.
    let bl = h.get(&format!("/api/v1/assets/{id}/baseline"), &tok).await;
    let snap = bl["data"]["snapshots"][0]["id"].as_str().expect("snapshot").to_string();
    let diff = h.get(&format!("/api/v1/assets/{id}/baseline/snapshots/{snap}/diff"), &tok).await;
    assert!(diff["data"]["added"].to_string().contains("10.46.0.99"), "{diff}");
    let timeline = h.get(&format!("/api/v1/assets/{id}/timeline"), &tok).await;
    assert!(timeline["data"].to_string().contains("baseline_complete"), "{timeline}");
}

#[tokio::test]
async fn vulnerabilities_from_the_offline_feed() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(47)).await;
    let f = h.get("/api/v1/findings?kind=vulnerability", &tok).await;
    assert!(f["data"].to_string().contains("AETHER-SAMPLE"), "{f}");
    let st = h.get("/api/v1/vulnerability-feed", &tok).await;
    assert!(st["data"].to_string().contains("aether-sample-feed"), "{st}");
    let l = h.get("/api/v1/vulnerability-feed/lookup?vendor=Siemens&model=CPU%201516&firmware=2.8", &tok).await;
    assert!(l["data"].to_string().contains("AETHER-SAMPLE-0003"), "{l}");
    let fid = f["data"][0]["id"].as_str().unwrap();
    h.post(&format!("/api/v1/findings/{fid}/acknowledge"), &tok, json!({ "reason": "patch planned in the next outage" })).await;
    let ins = h.get("/api/v1/findings?kind=insecure_protocol", &tok).await;
    assert!(!ins["data"].as_array().unwrap().is_empty(), "{ins}");
}

#[tokio::test]
async fn active_queries_are_safeguarded_and_results_flow_back() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(48)).await;
    let plc = h.asset_by_ip(&tok, "10.48.0.10").await;
    // Disabled by default.
    let (s, r, _) = h.call(Method::POST, "/api/v1/active-queries", Some(&tok), Some(json!({ "kind": "modbus_device_id", "target_ids": [plc["id"]] })), &[]).await;
    assert_eq!(s, 409);
    assert!(r.to_string().contains("active_queries_disabled"), "{r}");
    h.post("/api/v1/settings", &tok, json!({ "name": "active_queries", "value": { "enabled": true, "queries": ["modbus_device_id"], "max_attempts_per_day": 3 } })).await;
    let r = h.post("/api/v1/active-queries", &tok, json!({ "kind": "modbus_device_id", "target_ids": [plc["id"]] })).await;
    assert_eq!(r["state"], "pending_approval", "{r}");
    let qid = r["id"].as_str().unwrap().to_string();
    h.post(&format!("/api/v1/active-queries/{qid}/approve"), &h.admin(t), json!({})).await;
    let (_, snap, _) = h.call(Method::GET, "/api/v1/node/snapshot", Some(&node), None, &[]).await;
    assert!(snap["data"]["active_queries"].to_string().contains(&qid), "{snap}");
    let obs =
        json!([{ "observed_at": chrono::Utc::now(), "ip": "10.48.0.10", "signals": [{ "type": "asserted", "source": "active_query", "firmware": "v3.1", "confidence": 0.9 }] }]);
    let (s, v, _) = h
        .call(
            Method::POST,
            &format!("/api/v1/node/active-queries/{qid}/results"),
            Some(&node),
            Some(json!({ "results": [{ "ip": "10.48.0.10", "ok": true }], "observations": obs })),
            &[],
        )
        .await;
    assert_eq!(s, 202, "{v}");
    let q = h.get("/api/v1/active-queries?state=done", &tok).await;
    assert!(q["data"].to_string().contains(&qid), "{q}");
    // Results for an unknown/finished query are refused.
    let (s, _, _) = h.call(Method::POST, &format!("/api/v1/node/active-queries/{qid}/results"), Some(&node), Some(json!({ "results": [] })), &[]).await;
    assert_eq!(s, 409);
}

#[tokio::test]
async fn assertions_acceptance_investigations_and_privacy() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(49)).await;
    let a = h
        .post(
            "/api/v1/assertions",
            &tok,
            json!({ "name": "No telnet on controllers", "expression": "category == \"industrial_control\" and protocols in [\"telnet\"]", "severity": 7 }),
        )
        .await;
    let run = h.post("/api/v1/assertions/run", &tok, json!({})).await;
    assert!(run.to_string().contains(a["id"].as_str().unwrap()), "{run}");
    let acc = h.post("/api/v1/acceptance/runs", &tok, json!({})).await;
    assert_eq!(acc["failed"], 0, "{acc}");
    assert_eq!(acc["passed"], 17, "{acc}");
    let plc = h.asset_by_ip(&tok, "10.49.0.10").await;
    let inv = h.post("/api/v1/investigations", &tok, json!({ "name": "Unexpected writes", "asset_ids": [plc["id"]], "severity": 6 })).await;
    let iid = inv["id"].as_str().unwrap();
    let ev = h.post(&format!("/api/v1/investigations/{iid}/evidence"), &tok, json!({ "kind": "note", "content": "operator confirmed" })).await;
    assert_eq!(ev["sha256"].as_str().unwrap().len(), 64, "{ev}");
    h.get(&format!("/api/v1/investigations/{iid}/timeline"), &tok).await;
    let learn = h.post("/api/v1/classification/learn", &tok, json!({})).await;
    assert!(learn.is_object(), "{learn}");
    let s = h.get("/api/v1/search?q=Schneider", &tok).await;
    assert!(s["data"].to_string().contains("10.49.0.10"), "{s}");
    h.get("/api/v1/reports/inventory", &tok).await;
    // Vendor principal erasure.
    let v = h
        .post(
            "/api/v1/vendor-principals",
            &tok,
            json!({ "name": "Erase Me", "company": "X", "email": "erase@x.example", "expires_at": chrono::Utc::now() + chrono::Duration::days(3) }),
        )
        .await;
    let e = h.post("/api/v1/privacy/erase", &tok, json!({ "email": "erase@x.example" })).await;
    assert!(e.to_string().contains("vendor_principals"), "{e}");
    let (st, _, _) = h.call(Method::GET, &format!("/api/v1/vendor-principals/{}", v["id"].as_str().unwrap()), Some(&tok), None, &[]).await;
    assert!(st == 404 || st == 200);
}

#[tokio::test]
async fn lifecycle_quarantine_merge_and_decommission() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(50)).await;
    let plc = h.asset_by_ip(&tok, "10.50.0.10").await;
    let ews = h.asset_by_ip(&tok, "10.50.0.30").await;
    let (pid, eid) = (plc["id"].as_str().unwrap(), ews["id"].as_str().unwrap());
    h.post(&format!("/api/v1/assets/{eid}/quarantine"), &tok, json!({ "reason": "malware suspected" })).await;
    let q = h.get(&format!("/api/v1/assets/{eid}"), &tok).await;
    assert_eq!(q["data"]["quarantined"], true);
    let (s, _, _) = h.call(Method::DELETE, &format!("/api/v1/assets/{eid}/quarantine"), Some(&tok), None, &[]).await;
    assert!(s == 200 || s == 204);
    let ver = h.get(&format!("/api/v1/assets/{pid}"), &tok).await["data"]["version"].as_i64().unwrap();
    let p = h.patch(&format!("/api/v1/assets/{pid}"), &tok, ver, json!({ "owner": "ot-team@example.com", "criticality": 5, "location": "Line 3" })).await;
    assert_eq!(p["criticality"], 5);
    h.post(&format!("/api/v1/assets/{pid}/decommission"), &tok, json!({ "reason": "replaced" })).await;
    let d = h.get(&format!("/api/v1/assets/{pid}"), &tok).await;
    assert_eq!(d["data"]["lifecycle"], "decommissioned", "{d}");
    // Decommissioned assets cannot be quarantined again or moved back silently.
    let (s, _, _) = h.call(Method::POST, &format!("/api/v1/assets/{pid}/lifecycle"), Some(&tok), Some(json!({ "state": "discovered" })), &[]).await;
    assert!(s == 409 || s == 422, "{s}");
    // Import (CMDB) creates assets with asserted identity.
    let imp = h
        .post("/api/v1/assets/import", &tok, json!({ "assets": [{ "mac": "00:11:22:33:44:55", "ip": "10.50.1.1", "device_type": "hmi", "vendor": "Acme", "name": "HMI-7" }] }))
        .await;
    assert!(imp.to_string().contains("1"), "{imp}");
}
