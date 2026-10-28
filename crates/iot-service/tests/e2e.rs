//! End-to-end test against a running Aether platform.
//!
//! Skipped unless `IOT_E2E=1`. It registers this service with the platform
//! CLI, starts the control plane in-process on the product database,
//! registers the `iot.*` policy types, the `firewall.network` extension,
//! the `iot_*` log schemas and the policy hooks; enrols an edge appliance
//! through a platform provisioning key, captures an OT cell from a pcap
//! file, ships observations, logs, risk signals and events to the
//! platform; validates (through this service's reference hook), simulates
//! and activates an `iot.segmentation` policy through the change workflow
//! and checks that the edge enforces the verified artifact; and runs a
//! privileged remote-access request through the platform approval inbox
//! (step-up re-authentication, separation of duties) back into this
//! service.
//!
//! Environment (defaults in brackets): `AETHER_PLATFORM_URL`
//! [http://127.0.0.1:8080], `AETHER_ISSUER` [http://localhost:8080],
//! `AETHER_BIN` [aether], `AETHER_DATABASE_URL`
//! [postgres://aether:aether@localhost:5432/aether], `IOT_E2E_DATABASE_URL`
//! [postgres://aether_iot:aether_iot@localhost:5432/aether_iot],
//! `IOT_E2E_TENANT` [demo], `IOT_E2E_ADMIN` [admin@demo.local],
//! `IOT_E2E_PASSWORD` [Demo-Passw0rd!x].

mod common;

use base64::Engine as _;
use iot_service::config::{EdgeConfig, PlatformConfig, ServeConfig};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string())
}

struct Api {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Api {
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>, headers: &[(&str, &str)]) -> (u16, Value, reqwest::header::HeaderMap) {
        let mut rb = self.http.request(method, format!("{}{path}", self.base)).bearer_auth(&self.token);
        for (k, v) in headers {
            rb = rb.header(*k, *v);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let res = rb.send().await.expect("request");
        let status = res.status().as_u16();
        let h = res.headers().clone();
        let text = res.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)), h)
    }
    async fn get(&self, path: &str) -> Value {
        let (s, v, _) = self.call(reqwest::Method::GET, path, None, &[]).await;
        assert!(s < 300, "GET {path} -> {s}: {v}");
        v
    }
    async fn post(&self, path: &str, body: Value) -> Value {
        let (s, v, _) = self.call(reqwest::Method::POST, path, Some(body), &[("idempotency-key", &Uuid::now_v7().to_string())]).await;
        assert!(s < 300, "POST {path} -> {s}: {v}");
        v
    }
}

fn register_service(bin: &str, platform_db: &str, base_url: &str) -> (String, String) {
    let run = |rotate: bool| {
        let mut args = vec!["register-service", "--name", "aether-iot-ot", "--product", "iot", "--base-url", base_url, "--console-path", "/svc/iot", "--scopes", "svc.iot:nodes"];
        if rotate {
            args.push("--rotate-secret");
        }
        let out =
            std::process::Command::new(bin).args(&args).env("AETHER_DATABASE_URL", platform_db).env("AETHER_LOG", "error").output().expect("run the platform CLI (set AETHER_BIN)");
        assert!(out.status.success(), "register-service failed: {}", String::from_utf8_lossy(&out.stderr));
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let json: Value = serde_json::from_str(&text[text.find('{').expect("JSON output")..]).expect("register-service JSON");
        json
    };
    let mut json = run(false);
    if json["client_secret"].as_str().is_none() {
        json = run(true);
    }
    (json["client_id"].as_str().unwrap().to_string(), json["client_secret"].as_str().expect("client secret").to_string())
}

fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

async fn stage_policy(admin: &Api, ty: &str, default_action: &str, rules: Value) -> String {
    let set = admin.post(&format!("/api/v1/policy-sets/by-type/{ty}"), json!({})).await;
    let sid = set["data"]["id"].as_str().unwrap().to_string();
    let open = admin.get("/api/v1/changes?state=pending_approval,approved").await;
    for c in open["data"].as_array().unwrap() {
        if c["items"].as_array().map(|i| i.iter().any(|i| i["policy_set_id"] == sid)).unwrap_or(false) {
            admin.post(&format!("/api/v1/changes/{}/cancel", c["id"].as_str().unwrap()), json!({})).await;
        }
    }
    let (_, _, h) = admin.call(reqwest::Method::GET, &format!("/api/v1/policy-sets/{sid}/draft"), None, &[]).await;
    let etag = h.get("etag").and_then(|v| v.to_str().ok()).map(String::from);
    let headers: Vec<(&str, &str)> = etag.as_deref().map(|e| vec![("if-match", e)]).unwrap_or_default();
    let (s, v, _) = admin
        .call(reqwest::Method::PUT, &format!("/api/v1/policy-sets/{sid}/draft"), Some(json!({"policy_type": ty, "default_action": default_action, "rules": rules})), &headers)
        .await;
    assert!(s < 300, "draft for {ty} -> {s}: {v}");
    sid
}

async fn set_require_approval(admin: &Api, on: bool) {
    let (_, _, h) = admin.call(reqwest::Method::GET, "/api/v1/tenant/settings", None, &[]).await;
    let etag = h.get("etag").unwrap().to_str().unwrap().to_string();
    admin.call(reqwest::Method::PATCH, "/api/v1/tenant/settings", Some(json!({"changes": {"require_approval": on}})), &[("if-match", &etag)]).await;
}

async fn activate(admin: &Api, set_ids: &[String]) {
    let cr = admin.post("/api/v1/changes", json!({"title": "IoT/OT e2e policies", "policy_set_ids": set_ids})).await;
    let mut id = cr["data"]["id"].as_str().unwrap().to_string();
    if cr["data"]["state"] == "pending_approval" {
        // Single-administrator test: maker-checker is switched off for the
        // activation and restored afterwards.
        admin.post(&format!("/api/v1/changes/{id}/cancel"), json!({})).await;
        set_require_approval(admin, false).await;
        let cr = admin.post("/api/v1/changes", json!({"title": "IoT/OT e2e policies", "policy_set_ids": set_ids})).await;
        id = cr["data"]["id"].as_str().unwrap().to_string();
        set_require_approval(admin, true).await;
    }
    admin.post(&format!("/api/v1/changes/{id}/activate"), json!({})).await;
}

async fn wait_for<F, Fut>(what: &str, secs: u64, mut f: F) -> Value
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<Value>>,
{
    let start = Instant::now();
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn iot_ot_end_to_end() {
    if std::env::var("IOT_E2E").ok().as_deref() != Some("1") {
        eprintln!("skipping end-to-end test (set IOT_E2E=1 with a running platform)");
        return;
    }
    if std::env::var("IOT_LOG").is_ok() {
        aether_kit::telemetry::init_tracing(false, "IOT_LOG");
    }
    let platform_url = env("AETHER_PLATFORM_URL", "http://127.0.0.1:8080");
    let issuer = env("AETHER_ISSUER", "http://localhost:8080");
    let platform_db = env("AETHER_DATABASE_URL", "postgres://aether:aether@localhost:5432/aether");
    let http = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(30)).build().unwrap();
    let run = &Uuid::now_v7().simple().to_string()[20..];

    // 1. Register the service and start the control plane in-process.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let product_url = format!("http://{addr}");
    let (client_id, client_secret) = register_service(&env("AETHER_BIN", "aether"), &platform_db, &product_url);
    let pcfg = PlatformConfig { url: platform_url.clone(), issuer, audience: "aether".into(), client_id: Some(client_id), client_secret: Some(client_secret) };
    let mut cfg = ServeConfig::for_tests(&env("IOT_E2E_DATABASE_URL", "postgres://aether_iot:aether_iot@localhost:5432/aether_iot"), pcfg.clone());
    cfg.bind = addr.to_string();
    cfg.public_url = product_url.clone();
    let pool = aether_kit::db::connect(&cfg.database_url, 5, "iot-e2e").await.expect("product database");
    iot_service::migrate(&pool).await.expect("migrations");
    aether_kit::db::assert_rls_effective(&pool, true).await.expect("non-superuser role with effective RLS");
    let state = iot_service::state::AppState::new(pool, cfg).unwrap();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(listener, iot_service::api::router(st).into_make_service_with_connect_info::<SocketAddr>()).await });

    // 2. Policy types, extension, action owners, log schemas, hooks.
    assert_eq!(state.platform.register_policy_types().await.expect("policy types registered"), 3);
    assert_eq!(state.platform.register_log_schemas().await.expect("log schemas registered"), 7);
    state.platform.register_service_hooks().await.expect("service hooks declared");

    // 3. Administrator signed in through the platform.
    let creds = json!({"tenant": env("IOT_E2E_TENANT", "demo"), "email": env("IOT_E2E_ADMIN", "admin@demo.local"), "password": env("IOT_E2E_PASSWORD", "Demo-Passw0rd!x")});
    let login: Value = http.post(format!("{platform_url}/api/v1/auth/login")).json(&creds).send().await.unwrap().json().await.unwrap();
    let token = login["data"]["access_token"].as_str().expect("admin login").to_string();
    let claims: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let tenant = Uuid::parse_str(claims["tid"].as_str().unwrap()).unwrap();
    let admin = Api { http: http.clone(), base: platform_url.clone(), token: token.clone() };
    let product = Api { http: http.clone(), base: product_url.clone(), token: token.clone() };
    let schema = admin.get("/api/v1/log-schemas/iot_discovery").await;
    assert!(schema["data"]["fields"].to_string().contains("device_type"), "{schema}");
    let ext = admin.get("/api/v1/policy-types/firewall.network").await;
    assert!(ext.to_string().contains("iot."), "firewall.network extended with iot.* operands: {ext}");

    // 4. Zones and device groups (as the platform administrator).
    let zone = product.post("/api/v1/zones", json!({"name": format!("e2e cell {run}"), "key": format!("e2e_cell_{run}"), "security_level": 2, "mode": "enforce"})).await;
    let plcs = product
        .post("/api/v1/device-groups", json!({"name": format!("e2e PLCs {run}"), "key": format!("e2e_plcs_{run}"), "priority": 900, "match": {"device_types": ["plc"]}, "zone_id": zone["data"]["id"], "min_confidence": 0.5}))
        .await;
    let plcs = plcs["data"]["id"].as_str().unwrap().to_string();
    let site = product.post("/api/v1/sites", json!({"name": format!("e2e plant {run}"), "region": "eu", "criticality": 4})).await;

    // 5. Edge appliance enrolled through a platform provisioning key.
    let group = admin.post("/api/v1/node-groups", json!({"name": format!("IoT/OT e2e {run}"), "kind": "service_edge"})).await;
    let expires = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let key = admin.post("/api/v1/provisioning-keys", json!({"name": format!("iot-e2e-{run}"), "node_group_id": group["data"]["id"], "max_uses": 2, "expires_at": expires})).await;
    let state_dir = std::env::temp_dir().join(format!("iot-e2e-{run}")).to_string_lossy().to_string();
    let mut ecfg = EdgeConfig::for_tests(&state_dir, PlatformConfig { client_id: None, client_secret: None, ..pcfg.clone() });
    ecfg.name = format!("e2e-iot-edge-{run}");
    ecfg.provisioning_key = key["data"]["key"].as_str().map(String::from);
    ecfg.control_url = product_url.clone();
    let edge = iot_service::edge::Agent::start(ecfg).await.expect("edge enrolled");
    let nodes = admin.get(&format!("/api/v1/nodes?q={}", enc(&format!("e2e-iot-edge-{run}")))).await;
    assert!(nodes.to_string().contains(&edge.node_id.to_string()), "node visible in the platform: {nodes}");
    product
        .post(
            "/api/v1/sensors",
            json!({"name": format!("e2e edge {run}"), "site_id": site["data"]["id"], "kind": "edge_appliance", "node_id": edge.node_id.to_string(), "enforcement": true}),
        )
        .await;
    edge.sync_config().await.expect("first verified configuration");
    assert!(edge.runtime().snapshot["groups"].to_string().contains(&plcs));

    // 6. Passive capture: a pcap of an OT cell, shipped by the edge.
    let base = 200 + (Uuid::now_v7().as_u128() % 50) as u8;
    let pcap = std::path::Path::new(&state_dir).join("cell.pcap");
    std::fs::write(&pcap, iot_core::packet::write_pcap(&common::ot_frames(base))).unwrap();
    assert!(edge.ingest_pcap_file(&pcap).unwrap() >= 10);
    assert!(edge.flush().await.unwrap() >= 1, "observations shipped");
    let plc_ip = format!("10.{base}.0.10");
    let assets = product.get(&format!("/api/v1/assets?ip={plc_ip}")).await;
    let plc = assets["data"][0].clone();
    assert_eq!(plc["device_type"], "plc", "{assets}");
    assert!(plc["group_ids"].to_string().contains(&plcs), "{plc}");
    edge.sync_config().await.expect("snapshot with the new devices");

    // 7. Logs, risk signals and events reach the platform.
    let started = chrono::Utc::now() - chrono::Duration::minutes(5);
    assert!(iot_service::workers::ship_logs(&state).await.expect("log shipping") >= 1);
    let logs = admin.get(&format!("/api/v1/logs?log_type=iot_discovery&from={}", enc(&started.to_rfc3339()))).await;
    assert!(!logs["data"].as_array().unwrap().is_empty(), "iot_discovery logs in the platform: {logs}");
    let shipped = iot_service::workers::ship_signals(&state).await.expect("signal shipping");
    assert!(shipped >= 1, "risk signals accepted by the platform");
    let wl = admin.get("/api/v1/workloads?q=iot%3A&limit=200").await;
    assert!(
        wl["data"].as_array().map(|a| a.iter().any(|w| w["name"].as_str().unwrap_or("").starts_with("iot:"))).unwrap_or(false),
        "devices registered as workloads by risk signals: {wl}"
    );
    // The product database may hold other tenants (integration tests); those
    // are backed off by the relay while this tenant's events go through.
    wait_for("product events on the platform bus", 60, || async {
        iot_service::workers::relay(&state).await.expect("event relay");
        let v = admin.get("/api/v1/events?service=aether-iot-ot&limit=50").await;
        v["data"].as_array().filter(|a| !a.is_empty()).map(|_| v.clone())
    })
    .await;

    // 8. iot.segmentation through the platform: reference validation via the hook.
    let pred = |o: &str, op: &str, v: Value| json!({"pred": {"operand": o, "op": op, "values": v}});
    let set = admin.post("/api/v1/policy-sets/by-type/iot.segmentation", json!({})).await;
    let set_id = set["data"]["id"].as_str().unwrap().to_string();
    let mk = |g: &str| json!({"ruleset": {"policy_type": "iot.segmentation", "default_action": "allow", "rules": [{"id": Uuid::now_v7(), "name": "x", "order": 10, "action": "block", "condition": pred("destination.device_group", "in", json!([g]))}]}});
    let ok = admin.post(&format!("/api/v1/policy-sets/{set_id}/validate"), mk(&plcs)).await;
    assert_eq!(ok["data"]["valid"], true, "{ok}");
    let bad = admin.post(&format!("/api/v1/policy-sets/{set_id}/validate"), mk(&Uuid::now_v7().to_string())).await;
    assert_eq!(bad["data"]["valid"], false, "{bad}");
    let rules = json!([{"id": Uuid::now_v7(), "name": "Block writes to e2e PLCs", "order": 10, "action": "block",
        "condition": {"all": [pred("destination.device_group", "in", json!([plcs])), pred("network.operation_class", "in", json!(["write", "control", "program", "firmware"]))]}}]);
    let sid = stage_policy(&admin, "iot.segmentation", "allow", rules).await;
    // Platform simulation, enriched by this service with the device's groups.
    let sim = admin
        .post(
            &format!("/api/v1/policy-sets/{sid}/simulate"),
            json!({"target": "draft", "cases": [{"name": "write", "context": {"attrs": {"destination.ip": {"values": [plc_ip]}, "network.operation_class": {"values": ["write"]}}}, "expect_action": "block"}]}),
        )
        .await;
    assert_eq!(sim["data"]["failed"], 0, "simulation enriched by the product hook: {sim}");
    activate(&admin, std::slice::from_ref(&sid)).await;
    let rt = wait_for("verified iot.segmentation artifact on the edge", 60, || async {
        let _ = edge.sync_config().await;
        let rt = edge.runtime();
        rt.policy.is_some().then(|| json!({"config_version": rt.config_version}))
    })
    .await;
    let ews_ip = format!("10.{base}.0.30");
    let now = chrono::Utc::now();
    let rtm = edge.runtime();
    assert_eq!(rtm.decide(&ews_ip, &plc_ip, Some("modbus"), Some("read"), Some(502), now).enforced, "allow");
    let w = rtm.decide(&ews_ip, &plc_ip, Some("modbus"), Some("write"), Some(502), now);
    assert_eq!(w.enforced, "block", "{w:?}");
    edge.decisions.record(&w, &rtm.device(&ews_ip), &rtm.device(&plc_ip), Some("modbus"), Some("write"));
    edge.report().await.expect("status and decisions reported");
    // The control plane decides with the same active policy.
    state.invalidate(tenant);
    let d =
        product.post("/api/v1/segmentation/decide", json!({"source_ip": ews_ip, "destination_ip": plc_ip, "protocol": "modbus", "operation_class": "write", "port": 502})).await;
    assert_eq!(d["data"]["verdict"]["enforced"], "block", "{d}");
    assert_eq!(d["data"]["policy_source"], "active");

    // 9. Privileged remote access through the platform approval inbox.
    let tg =
        product.post("/api/v1/remote-targets", json!({"name": format!("e2e PLC console {run}"), "asset_id": plc["id"], "protocols": ["https"], "require_approval": true})).await;
    let vendor = product.post("/api/v1/vendor-principals", json!({"name": "E2E engineer", "company": "Integrator", "email": format!("eng-{run}@integrator.example"), "expires_at": chrono::Utc::now() + chrono::Duration::days(7)})).await;
    let window = |m: i64| json!({"target_id": tg["data"]["id"], "vendor_principal_id": vendor["data"]["id"], "protocol": "https", "window_start": chrono::Utc::now(), "window_end": chrono::Utc::now() + chrono::Duration::minutes(m), "justification": "e2e firmware review", "ticket": format!("WO-{run}")});
    // (a) Requested by this administrator: separation of duties in the inbox.
    let own = product.post("/api/v1/access-requests", window(60)).await;
    let own_approval = own["data"]["approval_id"].as_str().expect("approval created in the platform inbox").to_string();
    admin.post("/api/v1/auth/reauth", json!({"password": env("IOT_E2E_PASSWORD", "Demo-Passw0rd!x")})).await;
    let (s, v, _) = admin.call(reqwest::Method::POST, &format!("/api/v1/approvals/{own_approval}/approve"), Some(json!({"comment": "self"})), &[]).await;
    assert_eq!(s, 403, "the requester cannot decide: {v}");
    // (b) Requested by an API client (an automation acting for the vendor); approved by the administrator.
    let roles = admin.get("/api/v1/roles?limit=200").await;
    let role = roles["data"].as_array().unwrap().iter().find(|r| r["name"] == "Super Admin").expect("role")["id"].clone();
    let client = admin.post("/api/v1/api-clients", json!({"name": format!("iot-e2e-{run}"), "role_id": role, "token_ttl_secs": 900})).await;
    let cid = client["data"]["client_id"].as_str().unwrap().to_string();
    let csecret = client["data"]["client_secret"].as_str().expect("client secret").to_string();
    let tok: Value = http
        .post(format!("{platform_url}/api/v1/oauth/token"))
        .json(&json!({"grant_type": "client_credentials", "client_id": cid, "client_secret": csecret, "tenant_id": tenant}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let automation = Api { http: http.clone(), base: product_url.clone(), token: tok["access_token"].as_str().expect("api client token").to_string() };
    let req = automation.post("/api/v1/access-requests", window(60)).await;
    let rid = req["data"]["request"]["id"].as_str().unwrap().to_string();
    let approval = req["data"]["approval_id"].as_str().expect("approval created").to_string();
    let inbox = admin.get("/api/v1/approvals?state=pending").await;
    assert!(inbox.to_string().contains(&approval), "{inbox}");
    admin.post(&format!("/api/v1/approvals/{approval}/approve"), json!({"comment": "approved for the maintenance window"})).await;
    let approved = wait_for("approval decision mirrored into the access request", 30, || async {
        iot_service::workers::sync_approvals(&state, tenant).await.ok();
        let v = product.get(&format!("/api/v1/access-requests/{rid}")).await;
        (v["data"]["state"] == "approved").then_some(v)
    })
    .await;
    assert_eq!(approved["data"]["approval_id"], approval.as_str());
    let sess = automation.post(&format!("/api/v1/access-requests/{rid}/sessions"), json!({"client_ip": "198.51.100.10"})).await;
    let sid2 = sess["data"]["session_id"].as_str().unwrap();
    product.post(&format!("/api/v1/remote-sessions/{sid2}/end"), json!({})).await;
    // The administrator's own request is withdrawn (cancel mirrors to the inbox).
    product.post(&format!("/api/v1/access-requests/{}/cancel", own["data"]["request"]["id"].as_str().unwrap()), json!({})).await;
    let a = admin.get(&format!("/api/v1/approvals/{own_approval}")).await;
    assert_eq!(a["data"]["state"], "cancelled", "{a}");
    iot_service::workers::ship_logs(&state).await.unwrap();
    let ra = admin.get(&format!("/api/v1/logs?log_type=iot_remote_access&from={}", enc(&started.to_rfc3339()))).await;
    assert!(ra["data"].as_array().map(|a| a.len() >= 3).unwrap_or(false), "{ra}");

    // Clean-up: empty segmentation policy, revoke the node and the API client.
    let sid = stage_policy(&admin, "iot.segmentation", "allow", json!([])).await;
    activate(&admin, &[sid]).await;
    admin.post(&format!("/api/v1/nodes/{}/revoke", edge.node_id), json!({})).await;
    admin.call(reqwest::Method::DELETE, &format!("/api/v1/api-clients/{}", client["data"]["id"].as_str().unwrap()), None, &[]).await;
    std::fs::remove_dir_all(&state_dir).ok();
    eprintln!("e2e passed: config version {}, node {}", rt["config_version"], edge.node_id);
}
