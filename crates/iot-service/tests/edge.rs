//! Edge appliance against a mock platform (enrolment, node tokens,
//! heartbeat, signed manifest and artifacts, acknowledgements) and the
//! real control plane (snapshot, observations, status, decisions):
//! verified configuration, flow decisions, nftables rendering, capture
//! from pcap/TZSP, bounded queues, fail-static restart and tamper
//! detection, and the local API.

mod common;

use aether_core::policy::compile::{compile, BundleManifest, Target};
use aether_core::policy::{Condition, Op, Rule, RuleSet};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::*;
use iot_core::packet::{build, write_pcap, Mac};
use iot_service::config::{EdgeConfig, PlatformConfig};
use iot_service::edge::Agent;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
struct MockPlatform {
    tenant: Uuid,
    node: Uuid,
    token: String,
    config: Value,
    artifact: Value,
    seen: Arc<Mutex<Vec<(String, Value)>>>,
}

async fn start_platform(m: MockPlatform) -> String {
    let app = Router::new()
        .route(
            "/api/v1/nodes/enroll",
            post(|State(m): State<MockPlatform>, Json(b): Json<Value>| async move {
                m.seen.lock().unwrap().push(("enroll".into(), b.clone()));
                if b["provisioning_key"] != "pk-test" {
                    return (StatusCode::UNAUTHORIZED, Json(json!({ "code": "invalid_key" }))).into_response();
                }
                (StatusCode::CREATED, Json(json!({ "data": { "node_id": m.node, "tenant_id": m.tenant, "credential": "cred-secret" } }))).into_response()
            }),
        )
        .route(
            "/api/v1/nodes/token",
            post(|State(m): State<MockPlatform>, Json(b): Json<Value>| async move {
                if b["credential"] != "cred-secret" {
                    return (StatusCode::UNAUTHORIZED, Json(json!({}))).into_response();
                }
                Json(json!({ "access_token": m.token, "expires_at": chrono::Utc::now().timestamp() + 900 })).into_response()
            }),
        )
        .route(
            "/api/v1/node/heartbeat",
            post(|State(m): State<MockPlatform>, Json(b): Json<Value>| async move {
                m.seen.lock().unwrap().push(("heartbeat".into(), b));
                Json(json!({ "data": { "desired_config_version": 7 } }))
            }),
        )
        .route(
            "/api/v1/node/config",
            get(|State(m): State<MockPlatform>, h: HeaderMap| async move {
                let etag = "\"cfg-7\"";
                if h.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag) {
                    return StatusCode::NOT_MODIFIED.into_response();
                }
                let mut r: Response = Json(json!({ "data": m.config })).into_response();
                r.headers_mut().insert("etag", etag.parse().unwrap());
                r
            }),
        )
        .route("/api/v1/node/artifacts/{set}/{rev}", get(|State(m): State<MockPlatform>| async move { Json(json!({ "data": m.artifact })) }))
        .route(
            "/api/v1/node/ack",
            post(|State(m): State<MockPlatform>, Json(b): Json<Value>| async move {
                m.seen.lock().unwrap().push(("ack".into(), b));
                StatusCode::NO_CONTENT
            }),
        )
        .with_state(m);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await });
    format!("http://{addr}")
}

fn segmentation_policy(tenant: Uuid, plcs: &str) -> aether_core::policy::compile::CompiledPolicy {
    let t = iot_core::policy::types().into_iter().find(|t| t.key == "iot.segmentation").unwrap();
    let rs = RuleSet {
        policy_type: "iot.segmentation".into(),
        default_action: "allow".into(),
        default_params: Default::default(),
        rules: vec![Rule {
            id: Uuid::from_u128(77),
            name: "Block writes to PLCs".into(),
            description: String::new(),
            order: 1,
            enabled: true,
            condition: Condition::All(vec![
                Condition::pred("destination.device_group", Op::In, vec![json!(plcs)]),
                Condition::pred("network.operation_class", Op::In, vec![json!("write"), json!("control"), json!("program"), json!("firmware")]),
            ]),
            action: "block".into(),
            params: Default::default(),
            schedule: Default::default(),
            emergency: false,
            labels: vec![],
        }],
    };
    compile(&t, &rs, Target { tenant_id: tenant, policy_set_id: Uuid::from_u128(5), revision: 3 }).unwrap()
}

struct Setup {
    h: Harness,
    tenant: Uuid,
    platform: String,
    seen: Arc<Mutex<Vec<(String, Value)>>>,
    dir: String,
}

async fn setup(base: u8) -> Option<Setup> {
    let h = Harness::start().await?;
    let t = Uuid::now_v7();
    let tok = h.admin(t);
    let zone = h.post("/api/v1/zones", &tok, json!({ "name": "Cell", "key": "cell", "security_level": 2, "mode": "enforce" })).await;
    let plcs = h
        .post(
            "/api/v1/device-groups",
            &tok,
            json!({ "name": "PLCs", "key": "plcs", "priority": 100, "match": { "device_types": ["plc"] }, "zone_id": zone["id"], "min_confidence": 0.5 }),
        )
        .await;
    let (_, _, node, node_tok) = h.site_and_sensor(t).await;
    h.observe(&node_tok, ot_cell(base)).await;
    let c = segmentation_policy(t, plcs["id"].as_str().unwrap());
    let manifest = BundleManifest::build(t, 7, std::slice::from_ref(&c));
    let seen = Arc::new(Mutex::new(vec![]));
    let platform = start_platform(MockPlatform {
        tenant: t,
        node,
        token: node_tok,
        config: json!({ "config_version": 7, "enforcement": "enabled", "manifest": manifest }),
        artifact: serde_json::to_value(&c).unwrap(),
        seen: seen.clone(),
    })
    .await;
    let dir = std::env::temp_dir().join(format!("iot-edge-{}", Uuid::now_v7())).to_string_lossy().to_string();
    Some(Setup { h, tenant: t, platform, seen, dir })
}

fn edge_cfg(s: &Setup, platform: &str) -> EdgeConfig {
    let mut cfg = EdgeConfig::for_tests(&s.dir, PlatformConfig { url: platform.into(), issuer: ISSUER.into(), audience: "aether".into(), client_id: None, client_secret: None });
    cfg.control_url = s.h.base.clone();
    cfg.provisioning_key = Some("pk-test".into());
    cfg
}

#[tokio::test]
async fn enrol_sync_decide_capture_report_and_fail_static() {
    let Some(s) = setup(51).await else { return };
    let agent = Agent::start(edge_cfg(&s, &s.platform)).await.unwrap();
    // Enrolled once; credential stored with 0600.
    let cred = std::path::Path::new(&s.dir).join("credential.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&cred).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let rt = agent.runtime();
    assert_eq!(rt.config_version, 7);
    assert!(rt.policy.is_some(), "verified artifact loaded");
    assert!(rt.devices_by_ip.contains_key("10.51.0.10"));
    assert!(s.seen.lock().unwrap().iter().any(|(k, b)| k == "ack" && b["config_version"] == 7 && b["error"].is_null()));
    // Read allowed, write blocked (explicit rule, enforce zone).
    let now = chrono::Utc::now();
    assert_eq!(rt.decide("10.51.0.20", "10.51.0.10", Some("modbus"), Some("read"), Some(502), now).enforced, "allow");
    let w = rt.decide("10.51.0.30", "10.51.0.10", Some("modbus"), Some("write"), Some(502), now);
    assert_eq!(w.enforced, "block", "{w:?}");
    // Unchanged configuration: 304s, nothing re-applied.
    assert!(!agent.sync_config().await.unwrap());
    // nftables: group address set rendered.
    let nft = agent.render_nft(&agent.runtime());
    assert!(nft.contains("10.51.0.10"), "{nft}");
    // Capture: a pcap file with a new device; shipped to the control plane.
    let new_dev = (Mac([0x00, 0x1d, 0x9c, 51, 0, 77]), Ipv4Addr::new(10, 51, 0, 77), 44818u16);
    let peer = (Mac([0x00, 0x1b, 0x21, 51, 0, 30]), Ipv4Addr::new(10, 51, 0, 30), 50001u16);
    let pcap = write_pcap(&[(now.timestamp_micros(), build::tcp_frame(peer, new_dev, 0x02, &[])), (now.timestamp_micros() + 1, build::tcp_frame(new_dev, peer, 0x12, &[]))]);
    let file = std::path::Path::new(&s.dir).join("cap.pcap");
    std::fs::write(&file, pcap).unwrap();
    assert_eq!(agent.ingest_pcap_file(&file).unwrap(), 2);
    // TZSP-encapsulated frames too; garbage is counted, never fatal.
    assert!(agent.ingest_tzsp(now.timestamp_micros(), &build::tzsp(&build::tcp_frame(peer, new_dev, 0x10, &[]))));
    assert!(!agent.ingest_tzsp(now.timestamp_micros(), b"\x01\x02"));
    assert!(agent.flush().await.unwrap() >= 1);
    let tok = s.h.admin(s.tenant);
    let a = s.h.asset_by_ip(&tok, "10.51.0.77").await;
    assert_eq!(a["vendor"], "Rockwell Automation", "{a}");
    // Decisions and status reach the control plane.
    agent.decisions.record(&w, &rt.device("10.51.0.30"), &rt.device("10.51.0.10"), Some("modbus"), Some("write"));
    agent.report().await.unwrap();
    let sensors = s.h.get("/api/v1/sensors", &tok).await;
    assert!(sensors["data"][0]["last_seen_at"].is_string(), "{sensors}");
    let st = agent.status();
    assert_eq!(st["config"]["config_version"], 7);
    // Restart without the platform: the persisted configuration still enforces.
    drop(agent);
    let offline = Agent::start(edge_cfg(&s, "http://127.0.0.1:1")).await.unwrap();
    let rt = offline.runtime();
    assert_eq!(rt.config_version, 7);
    assert_eq!(rt.decide("10.51.0.30", "10.51.0.10", Some("modbus"), Some("write"), Some(502), chrono::Utc::now()).enforced, "block");
    // Tampered persisted state is refused (observe only until a verified sync).
    let p = std::path::Path::new(&s.dir).join("applied.json");
    let mut v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    v["snapshot"]["devices"] = json!([]);
    std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    let t2 = Agent::start(edge_cfg(&s, "http://127.0.0.1:1")).await.unwrap();
    assert_eq!(t2.runtime().config_version, 0);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[tokio::test]
async fn tampered_artifacts_are_rejected_and_reported() {
    let Some(s) = setup(52).await else { return };
    // The platform serves an artifact that does not match its self-hash.
    let t = s.tenant;
    let c = segmentation_policy(t, &Uuid::now_v7().to_string());
    let manifest = BundleManifest::build(t, 9, std::slice::from_ref(&c));
    let mut art = serde_json::to_value(&c).unwrap();
    art["default_action"] = json!("allow-everything");
    let seen = Arc::new(Mutex::new(vec![]));
    let (_, _, node, node_tok) = s.h.site_and_sensor(t).await;
    let platform = start_platform(MockPlatform {
        tenant: t,
        node,
        token: node_tok,
        config: json!({ "config_version": 9, "enforcement": "enabled", "manifest": manifest }),
        artifact: art,
        seen: seen.clone(),
    })
    .await;
    let dir = std::env::temp_dir().join(format!("iot-edge-{}", Uuid::now_v7())).to_string_lossy().to_string();
    let mut cfg = EdgeConfig::for_tests(&dir, PlatformConfig { url: platform, issuer: ISSUER.into(), audience: "aether".into(), client_id: None, client_secret: None });
    cfg.control_url = s.h.base.clone();
    cfg.provisioning_key = Some("pk-test".into());
    let agent = Agent::start(cfg).await.unwrap();
    assert_eq!(agent.runtime().config_version, 0, "nothing applied");
    assert!(seen.lock().unwrap().iter().any(|(k, b)| k == "ack" && b["config_version"] == 9 && b["error"].is_string()), "error acknowledged");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[tokio::test]
async fn wrong_provisioning_key_and_bounded_queue() {
    let Some(s) = setup(53).await else { return };
    let mut cfg = edge_cfg(&s, &s.platform);
    cfg.provisioning_key = Some("wrong".into());
    assert!(Agent::start(cfg).await.is_err());
    // Offline agent: queue bounded, oldest dropped.
    let a = Agent::offline(edge_cfg(&s, "http://127.0.0.1:1"), iot_service::edge::Runtime::empty()).unwrap();
    for i in 0..10 {
        a.enqueue(json!({ "batch_id": format!("b{i}"), "observations": [] }));
    }
    assert_eq!(a.queue.lock().unwrap().len(), 4);
    assert_eq!(a.dropped_batches.load(std::sync::atomic::Ordering::Relaxed), 6);
    // Fuzzed frames never crash the collector.
    let mut rng = iot_core::packet::XorShift(7);
    let base = build::tcp_frame(
        (Mac([0, 1, 2, 3, 4, 5]), Ipv4Addr::new(10, 0, 0, 1), 1000),
        (Mac([0, 1, 2, 3, 4, 6]), Ipv4Addr::new(10, 0, 0, 2), 502),
        0x18,
        &iot_core::protocols::modbus::adu(1, 1, &[3, 0, 0, 0, 1]),
    );
    for _ in 0..2000 {
        a.ingest_frame(0, &rng.mutate(&base));
    }
    assert_eq!(a.parser_panics.load(std::sync::atomic::Ordering::Relaxed), 0);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[tokio::test]
async fn local_api_requires_the_admin_token() {
    let Some(s) = setup(54).await else { return };
    let agent = Agent::start(edge_cfg(&s, &s.platform)).await.unwrap();
    let app = iot_service::edge::admin::router(agent.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await });
    let base = format!("http://{addr}");
    let (st, _, _) = s.h.call(Method::GET, &format!("{base}/health/ready"), None, None, &[]).await;
    assert_eq!(st, 200);
    let body = json!({ "src_ip": "10.54.0.30", "dst_ip": "10.54.0.10", "protocol": "modbus", "operation_class": "write", "port": 502 });
    let (st, _, _) = s.h.call(Method::POST, &format!("{base}/v1/decide"), Some("wrong"), Some(body.clone()), &[]).await;
    assert_eq!(st, 401);
    let (st, v, _) = s.h.call(Method::POST, &format!("{base}/v1/decide"), Some("test-admin-token"), Some(body), &[]).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["verdict"]["enforced"], "block", "{v}");
    let (st, v, _) = s.h.call(Method::GET, &format!("{base}/status"), Some("test-admin-token"), None, &[]).await;
    assert_eq!(st, 200);
    assert_eq!(v["config"]["policy_loaded"], true);
    let (st, m, _) = s.h.call(Method::GET, &format!("{base}/metrics"), None, None, &[]).await;
    assert_eq!(st, 200);
    assert!(m.as_str().unwrap_or_default().contains("aether_iot_edge"));
    let _ = std::fs::remove_dir_all(&s.dir);
}
