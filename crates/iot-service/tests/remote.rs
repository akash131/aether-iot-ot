//! Privileged remote access: vendor principals, JIT windows, approvals with
//! separation of duties, sessions brokered through Private Access,
//! recording metadata, termination and the supervision worker; plus the
//! peer integrations (branch inventory, firewall identity bindings).

mod common;

use chrono::{Duration, Utc};
use common::*;
use serde_json::json;
use uuid::Uuid;

async fn target(h: &Harness, t: Uuid, console: Option<&str>) -> (String, String) {
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(44)).await;
    let plc = h.asset_by_ip(&tok, "10.44.0.10").await;
    let tg = h
        .post(
            "/api/v1/remote-targets",
            &tok,
            json!({ "name": "PLC-1 web console", "asset_id": plc["id"], "console_id": console, "protocols": ["https", "rdp"], "require_approval": true }),
        )
        .await;
    let vendor = h
        .post(
            "/api/v1/vendor-principals",
            &tok,
            json!({ "name": "Field engineer", "company": "Integrator Ltd", "email": "Eng@Integrator.example", "expires_at": Utc::now() + Duration::days(30) }),
        )
        .await;
    (tg["id"].as_str().unwrap().into(), vendor["id"].as_str().unwrap().into())
}

#[tokio::test]
async fn jit_window_approval_session_recording_and_end() {
    let Some(h) = Harness::with_peers().await else { return };
    let t = Uuid::now_v7();
    let requester = h.admin(t);
    let approver = h.admin(t);
    let (tg, vendor) = target(&h, t, Some("console-plc-1")).await;
    let now = Utc::now();
    let body = json!({ "target_id": tg, "vendor_principal_id": vendor, "protocol": "https", "window_start": now - Duration::minutes(1), "window_end": now + Duration::hours(2), "justification": "firmware review", "ticket": "WO-1234" });
    let r = h.post("/api/v1/access-requests", &requester, body.clone()).await;
    assert_eq!(r["outcome"], "pending_approval", "{r}");
    let id = r["request"]["id"].as_str().unwrap().to_string();
    // Not approved yet: no session.
    let (s, _, _) = h.call(Method::POST, &format!("/api/v1/access-requests/{id}/sessions"), Some(&requester), Some(json!({})), &[]).await;
    assert_eq!(s, 409);
    // Separation of duties.
    let (s, _, _) = h.call(Method::POST, &format!("/api/v1/access-requests/{id}/approve"), Some(&requester), Some(json!({})), &[]).await;
    assert_eq!(s, 403);
    let a = h.post(&format!("/api/v1/access-requests/{id}/approve"), &approver, json!({ "comment": "ok" })).await;
    assert_eq!(a["state"], "approved", "{a}");
    // The window was granted through Private Access.
    assert!(h.seen.lock().unwrap().iter().any(|(p, op, d)| p == "pa" && op == "grant" && d["console"] == "console-plc-1" && d["email"] == "eng@integrator.example"));
    let s = h.post(&format!("/api/v1/access-requests/{id}/sessions"), &requester, json!({ "client_ip": "198.51.100.7" })).await;
    let sid = s["session_id"].as_str().unwrap().to_string();
    assert_eq!(s["launch"]["console_id"], "console-plc-1");
    // One live session per request.
    let (st, _, _) = h.call(Method::POST, &format!("/api/v1/access-requests/{id}/sessions"), Some(&requester), Some(json!({})), &[]).await;
    assert_eq!(st, 409);
    // Recording metadata (content stays with the broker).
    let rec = json!({ "recording_id": "rec-1", "sha256": "a".repeat(64), "size_bytes": 1024, "duration_ms": 60000, "stored_by": "private_access" });
    h.put(&format!("/api/v1/remote-sessions/{sid}/recording"), &requester, rec).await;
    let (st, _, _) = h
        .call(
            Method::PUT,
            &format!("/api/v1/remote-sessions/{sid}/recording"),
            Some(&requester),
            Some(json!({ "recording_id": "r", "sha256": "xyz", "size_bytes": 1, "duration_ms": 1, "stored_by": "x" })),
            &[],
        )
        .await;
    assert_eq!(st, 422);
    h.post(&format!("/api/v1/remote-sessions/{sid}/terminate"), &approver, json!({ "reason": "suspicious" })).await;
    let one = h.get(&format!("/api/v1/remote-sessions/{sid}"), &requester).await;
    assert!(one["data"]["ended_at"].is_string(), "{one}");
    assert_eq!(one["data"]["recording"]["sha256"], "a".repeat(64));
    // Revoking the request revokes the broker grant.
    h.post(&format!("/api/v1/access-requests/{id}/revoke"), &approver, json!({})).await;
    assert!(h.seen.lock().unwrap().iter().any(|(p, op, _)| p == "pa" && op == "revoke"));
    // Typed logs record the lifecycle.
    let n = h.scalar(t, "SELECT to_jsonb(count(*)) FROM log_outbox WHERE record->>'log_type' = 'iot_remote_access'").await;
    assert!(n.as_i64().unwrap() >= 3, "{n}");
}

#[tokio::test]
async fn windows_and_principals_are_validated() {
    let Some(h) = Harness::start().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (tg, vendor) = target(&h, t, None).await;
    let now = Utc::now();
    let req = |s: chrono::DateTime<Utc>, e: chrono::DateTime<Utc>, proto: &str| json!({ "target_id": tg, "vendor_principal_id": vendor, "protocol": proto, "window_start": s, "window_end": e, "justification": "scheduled maintenance" });
    // Too long, reversed, unsupported protocol.
    for b in [req(now, now + Duration::hours(30), "https"), req(now + Duration::hours(2), now, "https"), req(now, now + Duration::hours(1), "vnc")] {
        let (s, v, _) = h.call(Method::POST, "/api/v1/access-requests", Some(&tok), Some(b), &[]).await;
        assert_eq!(s, 422, "{v}");
    }
    // Disabled vendor principal.
    let vp = h.get(&format!("/api/v1/vendor-principals/{vendor}"), &tok).await;
    h.patch(&format!("/api/v1/vendor-principals/{vendor}"), &tok, vp["data"]["version"].as_i64().unwrap(), json!({ "enabled": false })).await;
    let (s, v, _) = h.call(Method::POST, "/api/v1/access-requests", Some(&tok), Some(req(now, now + Duration::hours(1), "https")), &[]).await;
    assert_eq!(s, 422, "{v}");
    // A future window: approved, but the session cannot start early (JIT).
    let (tg2, vendor2) = (tg.clone(), {
        let v = h.post("/api/v1/vendor-principals", &tok, json!({ "name": "B", "company": "C", "email": "b@c.example", "expires_at": now + Duration::days(5) })).await;
        v["id"].as_str().unwrap().to_string()
    });
    let r = h
        .post("/api/v1/access-requests", &tok, json!({ "target_id": tg2, "vendor_principal_id": vendor2, "window_start": now + Duration::hours(3), "window_end": now + Duration::hours(4), "justification": "scheduled maintenance later" }))
        .await;
    let id = r["request"]["id"].as_str().unwrap();
    h.post(&format!("/api/v1/access-requests/{id}/approve"), &h.admin(t), json!({})).await;
    let (s, v, _) = h.call(Method::POST, &format!("/api/v1/access-requests/{id}/sessions"), Some(&tok), Some(json!({})), &[]).await;
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["code"], "window_not_started", "{v}");
}

#[tokio::test]
async fn supervision_ends_sessions_after_the_window() {
    let Some(h) = Harness::with_peers().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (tg, vendor) = target(&h, t, Some("console-1")).await;
    let now = Utc::now();
    let r = h
        .post("/api/v1/access-requests", &tok, json!({ "target_id": tg, "vendor_principal_id": vendor, "window_start": now - Duration::minutes(1), "window_end": now + Duration::minutes(30), "justification": "scheduled maintenance" }))
        .await;
    let id = r["request"]["id"].as_str().unwrap().to_string();
    h.post(&format!("/api/v1/access-requests/{id}/approve"), &h.admin(t), json!({})).await;
    let s = h.post(&format!("/api/v1/access-requests/{id}/sessions"), &tok, json!({})).await;
    let sid = Uuid::parse_str(s["session_id"].as_str().unwrap()).unwrap();
    // The window closes (simulated by moving it into the past).
    let mut tx = aether_kit::db::tenant_tx(&h.pool, t).await.unwrap();
    sqlx::query("UPDATE access_requests SET window_end = now() - interval '1 minute' WHERE id = $1").bind(Uuid::parse_str(&id).unwrap()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let n = iot_service::workers::supervise_remote(&h.state, t).await.unwrap();
    assert!(n >= 1);
    let one = h.get(&format!("/api/v1/remote-sessions/{sid}"), &tok).await;
    assert!(one["data"]["ended_at"].is_string(), "{one}");
    assert_eq!(one["data"]["end_reason"], "window_ended", "{one}");
}

#[tokio::test]
async fn branch_inventory_and_firewall_bindings() {
    let Some(h) = Harness::with_peers().await else { return };
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let (_, _, _, node) = h.site_and_sensor(t).await;
    h.observe(&node, ot_cell(45)).await;
    let n = iot_service::workers::pull_branch(&h.state, t).await.unwrap();
    assert!(n >= 1);
    let cam = h.asset_by_ip(&tok, "10.77.0.5").await;
    assert_eq!(cam["device_type"], "ip_camera", "{cam}");
    let n = iot_service::workers::push_firewall(&h.state, t).await.unwrap();
    assert!(n >= 3, "{n}");
    assert!(h.seen.lock().unwrap().iter().any(|(p, _, d)| p == "firewall" && d.to_string().contains("10.45.0.10")));
    let i = h.get("/api/v1/integrations", &tok).await;
    assert!(i.to_string().contains("fake_private_access"), "{i}");
}
