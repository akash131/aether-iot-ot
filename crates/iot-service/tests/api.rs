//! Control-plane API: conventions, tenant isolation, discovery pipeline,
//! classification, risk, findings, anomalies and operations endpoints.

mod common;

use aether_kit::ActorType;
use common::*;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn conventions_auth_envelopes_problems_versions_idempotency_pagination() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    // Unauthenticated and unentitled callers.
    let (s, _, _) = h.call(Method::GET, "/api/v1/sites", None, None, &[]).await;
    assert_eq!(s, 401);
    let noent = h.token(t, ActorType::Admin, ALL, &["si"]);
    let (s, v, _) = h.call(Method::GET, "/api/v1/assets", Some(&noent), None, &[]).await;
    assert_eq!(s, 403, "{v}");
    let ro = h.token(t, ActorType::Admin, &["policy.iot:read"], &["iot"]);
    let (s, _, _) = h.call(Method::POST, "/api/v1/sites", Some(&ro), Some(json!({ "name": "x" })), &[]).await;
    assert_eq!(s, 403);
    // Nodes are refused on administrative APIs.
    let node = h.node_token(t, Uuid::now_v7(), "service_edge");
    let (s, _, _) = h.call(Method::GET, "/api/v1/assets", Some(&node), None, &[]).await;
    assert_eq!(s, 403);
    // ...and administrators on node APIs.
    let (s, _, _) = h.call(Method::POST, "/api/v1/node/observations", Some(&tok), Some(json!({ "observations": [] })), &[]).await;
    assert_eq!(s, 403);
    // Problem details on validation errors.
    let (s, v, hd) = h.call(Method::POST, "/api/v1/sites", Some(&tok), Some(json!({ "criticality": 9 })), &[]).await;
    assert_eq!(s, 422, "{v}");
    assert!(hd["content-type"].to_str().unwrap().contains("problem+json"));
    // Idempotency-Key replays the first result.
    let (s1, a, _) = h.call(Method::POST, "/api/v1/sites", Some(&tok), Some(json!({ "name": "Plant A" })), &[("idempotency-key", "k-1")]).await;
    let (s2, b, _) = h.call(Method::POST, "/api/v1/sites", Some(&tok), Some(json!({ "name": "Plant A" })), &[("idempotency-key", "k-1")]).await;
    assert_eq!((s1, s2), (201, 201), "{a} {b}");
    assert_eq!(a["data"]["id"], b["data"]["id"]);
    let id = a["data"]["id"].as_str().unwrap().to_string();
    // If-Match is required and checked.
    let (s, _, _) = h.call(Method::PATCH, &format!("/api/v1/sites/{id}"), Some(&tok), Some(json!({ "region": "eu" })), &[]).await;
    assert_eq!(s, 428);
    let (s, _, _) = h.call(Method::PATCH, &format!("/api/v1/sites/{id}"), Some(&tok), Some(json!({ "region": "eu" })), &[("if-match", "\"v9\"")]).await;
    assert_eq!(s, 412);
    h.patch(&format!("/api/v1/sites/{id}"), &tok, 1, json!({ "region": "eu" })).await;
    // Cursor pagination.
    for i in 0..4 {
        h.post("/api/v1/sites", &tok, json!({ "name": format!("Plant {i}") })).await;
    }
    let p1 = h.get("/api/v1/sites?limit=2", &tok).await;
    assert_eq!(p1["data"].as_array().unwrap().len(), 2);
    let cur = p1["meta"]["next_cursor"].as_str().expect("next cursor").to_string();
    let p2 = h.get(&format!("/api/v1/sites?limit=2&cursor={cur}"), &tok).await;
    assert_ne!(p1["data"][0]["id"], p2["data"][0]["id"]);
    // Every mutation is audited and emits an outbox event.
    assert!(h.count("audit_events", t).await >= 6);
    assert!(h.count("outbox_events", t).await >= 6);
    // Console metadata.
    let meta = h.get("/api/v1/meta/resources", &tok).await;
    assert!(meta.to_string().contains("device-groups"), "{meta}");
}

#[tokio::test]
async fn tenants_are_isolated() {
    let Some(h) = Harness::start().await else { return };
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    let (_, _, _, node_a) = h.site_and_sensor(a).await;
    h.observe(&node_a, ot_cell(41)).await;
    let ta = h.admin(a);
    let tb = h.admin(b);
    let la = h.get("/api/v1/assets", &ta).await;
    assert!(la["data"].as_array().unwrap().len() >= 3, "{la}");
    let lb = h.get("/api/v1/assets", &tb).await;
    assert_eq!(lb["data"].as_array().unwrap().len(), 0);
    let id = la["data"][0]["id"].as_str().unwrap();
    let (s, _, _) = h.call(Method::GET, &format!("/api/v1/assets/{id}"), Some(&tb), None, &[]).await;
    assert_eq!(s, 404);
    // A node of tenant B cannot post as a sensor of tenant A.
    let nb = h.node_token(b, Uuid::now_v7(), "service_edge");
    let (s, v, _) = h.call(Method::POST, "/api/v1/node/observations", Some(&nb), Some(json!({ "observations": [] })), &[]).await;
    assert_eq!(s, 409, "{v}");
}

#[tokio::test]
async fn passive_discovery_classifies_scores_and_explains() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    let out = h.observe(&node, ot_cell(42)).await;
    eprintln!("ingest: {out}");
    assert!(out["assets"].as_u64().unwrap_or(0) >= 3 || out.to_string().contains("created"), "{out}");
    let plc = h.asset_by_ip(&tok, "10.42.0.10").await;
    assert_eq!(plc["device_type"], "plc", "{plc}");
    assert_eq!(plc["vendor"], "Schneider Electric");
    assert!(plc["protocols"].as_array().unwrap().iter().any(|p| p == "modbus"));
    assert!(plc["confidence"].as_f64().unwrap() >= 0.7);
    assert!(plc["risk_score"].as_i64().unwrap() > 0);
    let id = plc["id"].as_str().unwrap();
    // Explanation: evidence with rules and facts.
    let c = h.get(&format!("/api/v1/assets/{id}/classification"), &tok).await;
    assert!(c["data"]["evidence"].as_array().map(|e| !e.is_empty()).unwrap_or(false) || c.to_string().contains("rule"), "{c}");
    let r = h.get(&format!("/api/v1/assets/{id}/risk"), &tok).await;
    assert!(r.to_string().contains("factors"), "{r}");
    // Insecure protocol (telnet) finding on the PLC.
    let f = h.get(&format!("/api/v1/assets/{id}/findings"), &tok).await;
    assert!(f.to_string().contains("telnet") || f.to_string().contains("insecure"), "{f}");
    // Override wins and is explained.
    let (s, v, _) = h
        .call(
            Method::PUT,
            &format!("/api/v1/assets/{id}/override"),
            Some(&tok),
            Some(json!({ "device_type": "rtu", "vendor": "Schneider Electric", "reason": "site survey" })),
            &[],
        )
        .await;
    assert!(s == 200 || s == 201, "{v}");
    let a = h.get(&format!("/api/v1/assets/{id}"), &tok).await;
    assert_eq!(a["data"]["device_type"], "rtu", "{a}");
    let (s, _, _) = h.call(Method::DELETE, &format!("/api/v1/assets/{id}/override"), Some(&tok), None, &[]).await;
    assert!(s == 200 || s == 204);
    let a = h.get(&format!("/api/v1/assets/{id}"), &tok).await;
    assert_eq!(a["data"]["device_type"], "plc");
    // Inventory search, summary and export.
    let sum = h.get("/api/v1/inventory/summary", &tok).await;
    assert!(sum.to_string().contains("plc"), "{sum}");
    let (s, csv, _) = h.call(Method::GET, "/api/v1/assets/export", Some(&tok), None, &[]).await;
    assert_eq!(s, 200);
    assert!(csv.as_str().unwrap_or_default().contains("10.42.0.10"));
    // Typed logs were queued for the platform.
    assert!(h.count("log_outbox", t).await > 0);
}

#[tokio::test]
async fn operations_catalogues() {
    let Some(h) = Harness::start().await else { return };
    let tok = h.admin(Uuid::now_v7());
    let c = h.get("/api/v1/capabilities", &tok).await;
    assert_eq!(
        c["data"].as_array().map(|a| a.len()).unwrap_or(c["data"]["capabilities"].as_array().map(|a| a.len()).unwrap_or(0)),
        134,
        "{}",
        &c.to_string()[..300.min(c.to_string().len())]
    );
    let s = h.get("/api/v1/schemas", &tok).await;
    assert!(s.to_string().contains("ZTE-IOTDATA-153160"));
    let f = h.get("/api/v1/failure-modes", &tok).await;
    assert!(f.to_string().contains("parser"), "{f}");
    for p in [
        "/api/v1/taxonomy",
        "/api/v1/protocols",
        "/api/v1/integrations",
        "/api/v1/status",
        "/api/v1/dashboards/overview",
        "/api/v1/dashboards/risk",
        "/api/v1/graph",
        "/api/v1/vulnerability-feed",
    ] {
        h.get(p, &tok).await;
    }
    let (s, _, _) = h.call(Method::GET, "/health/ready", None, None, &[]).await;
    assert_eq!(s, 200);
}
