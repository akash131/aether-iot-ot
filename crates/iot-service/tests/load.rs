//! Load driver (skipped unless `IOT_LOAD=1`; needs `IOT_TEST_DATABASE_URL`).
//!
//! Measures, and prints as JSON for docs/performance.md:
//! * passive collection: frames/s through the collector (decode, parse,
//!   fingerprint) on one core;
//! * ingestion: observations/s through `POST /api/v1/node/observations`
//!   with concurrent edges, and batch latency percentiles;
//! * edge decisions: flow decisions/s and latency of the in-memory runtime
//!   with a compiled `iot.segmentation` policy;
//! * control-plane decisions: `POST /api/v1/segmentation/decide` latency.
//!
//! Tunables: `IOT_LOAD_CELLS` [300], `IOT_LOAD_EDGES` [8], `IOT_LOAD_DECISIONS` [200000].

mod common;

use common::*;
use serde_json::json;
use std::time::Instant;
use uuid::Uuid;

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return 0.0;
    }
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn n(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn load() {
    if std::env::var("IOT_LOAD").ok().as_deref() != Some("1") {
        eprintln!("skipping load driver (set IOT_LOAD=1)");
        return;
    }
    let Some(h) = Harness::start_with(
        |mut c| {
            c.ingest_concurrency = 32;
            c
        },
        false,
    )
    .await
    else {
        return;
    };
    let cells = n("IOT_LOAD_CELLS", 300);
    let edges = n("IOT_LOAD_EDGES", 8);
    let decisions = n("IOT_LOAD_DECISIONS", 200_000);

    // 1. Collector throughput.
    let frames: Vec<(i64, Vec<u8>)> = (0..cells).flat_map(|i| ot_frames((i % 250) as u8)).collect();
    let mut c = iot_core::collect::Collector::default();
    let t = Instant::now();
    for _ in 0..5 {
        for (ts, f) in &frames {
            c.ingest(*ts, f);
        }
    }
    let collector_fps = (frames.len() * 5) as f64 / t.elapsed().as_secs_f64();

    // 2. Ingestion through the node API with concurrent edges.
    let tenant = Uuid::now_v7();
    let tok = h.admin(tenant);
    let zone = h.post("/api/v1/zones", &tok, json!({ "name": "Load", "key": "load", "security_level": 2, "mode": "enforce" })).await;
    let plcs = h.post("/api/v1/device-groups", &tok, json!({ "name": "PLCs", "key": "plcs", "priority": 10, "match": { "device_types": ["plc"] }, "zone_id": zone["id"] })).await;
    let mut nodes = vec![];
    for _ in 0..edges {
        nodes.push(h.site_and_sensor(tenant).await.3);
    }
    let per_edge: Vec<Vec<iot_core::model::Observation>> = (0..edges)
        .map(|e| {
            (0..cells / edges)
                .flat_map(|i| {
                    let mut obs = ot_cell(((e * 31 + i) % 250) as u8);
                    // Distinct devices per edge and cell.
                    for (k, o) in obs.iter_mut().enumerate() {
                        o.ip = Some(format!("10.{}.{}.{}", 100 + e, i % 250, 10 + k));
                        o.mac = Some(format!("02:{:02x}:{:02x}:{:02x}:00:{:02x}", e, i / 250, i % 250, k));
                    }
                    obs
                })
                .collect()
        })
        .collect();
    let total_obs: usize = per_edge.iter().map(|v| v.len()).sum();
    let t = Instant::now();
    let mut tasks = vec![];
    for (e, obs) in per_edge.into_iter().enumerate() {
        let http = h.http.clone();
        let base = h.base.clone();
        let token = nodes[e].clone();
        tasks.push(tokio::spawn(async move {
            let mut lat = vec![];
            for chunk in obs.chunks(60) {
                let s = Instant::now();
                let r = http
                    .post(format!("{base}/api/v1/node/observations"))
                    .bearer_auth(&token)
                    .json(&json!({ "batch_id": Uuid::now_v7().to_string(), "observations": chunk }))
                    .send()
                    .await
                    .unwrap();
                assert!(r.status().is_success(), "{}", r.status());
                lat.push(s.elapsed().as_secs_f64() * 1000.0);
            }
            lat
        }));
    }
    let mut lat = vec![];
    for t in tasks {
        lat.extend(t.await.unwrap());
    }
    let ingest_secs = t.elapsed().as_secs_f64();
    let assets = h.count("assets", tenant).await;

    // 3. Edge decisions with a compiled policy.
    let ty = iot_core::policy::types().into_iter().find(|t| t.key == "iot.segmentation").unwrap();
    let rs = aether_core::policy::RuleSet {
        policy_type: "iot.segmentation".into(),
        default_action: "allow".into(),
        default_params: Default::default(),
        rules: (0..50)
            .map(|i| aether_core::policy::Rule {
                id: iot_core::stable_uuid(&format!("r{i}")),
                name: format!("rule {i}"),
                description: String::new(),
                order: i + 1,
                enabled: true,
                condition: aether_core::policy::Condition::All(vec![
                    aether_core::policy::Condition::pred(
                        "destination.device_group",
                        aether_core::policy::Op::In,
                        vec![json!(if i == 49 { plcs["id"].clone() } else { json!(Uuid::now_v7().to_string()) })],
                    ),
                    aether_core::policy::Condition::pred("network.operation_class", aether_core::policy::Op::In, vec![json!("write")]),
                ]),
                action: "block".into(),
                params: Default::default(),
                schedule: Default::default(),
                emergency: false,
                labels: vec![],
            })
            .collect(),
    };
    let compiled = aether_core::policy::compile::compile(&ty, &rs, aether_core::policy::compile::Target { tenant_id: tenant, policy_set_id: Uuid::now_v7(), revision: 1 }).unwrap();
    let node = h.node_token(tenant, Uuid::now_v7(), "service_edge");
    let _ = node;
    let (_, snap, _) = h.call(Method::GET, "/api/v1/node/snapshot", Some(&nodes[0]), None, &[]).await;
    let rt = iot_service::edge::Runtime::build(1, false, &[compiled], snap["data"].clone());
    let ips: Vec<String> = rt.devices_by_ip.keys().cloned().collect();
    let now = chrono::Utc::now();
    let mut dl = vec![];
    let t = Instant::now();
    let mut blocked = 0;
    for i in 0..decisions {
        let s = Instant::now();
        let v = rt.decide(&ips[i % ips.len()], &ips[(i * 7 + 3) % ips.len()], Some("modbus"), Some(if i % 2 == 0 { "write" } else { "read" }), Some(502), now);
        if i % 100 == 0 {
            dl.push(s.elapsed().as_secs_f64() * 1e6);
        }
        if v.enforced == "block" {
            blocked += 1;
        }
    }
    let edge_dps = decisions as f64 / t.elapsed().as_secs_f64();

    // 4. Control-plane decide latency.
    let mut cl = vec![];
    for i in 0..300 {
        let s = Instant::now();
        let body = json!({ "source_ip": ips[i % ips.len()], "destination_ip": ips[(i + 1) % ips.len()], "protocol": "modbus", "operation_class": "write", "ruleset": rs });
        let (st, _, _) = h.call(Method::POST, "/api/v1/segmentation/decide", Some(&tok), Some(body), &[]).await;
        assert_eq!(st, 200);
        cl.push(s.elapsed().as_secs_f64() * 1000.0);
    }

    let out = json!({
        "collector": { "frames": frames.len() * 5, "frames_per_sec": collector_fps.round() },
        "ingest": { "edges": edges, "observations": total_obs, "assets": assets, "seconds": (ingest_secs * 100.0).round() / 100.0, "observations_per_sec": (total_obs as f64 / ingest_secs).round(),
                    "batch_ms_p50": pct(&mut lat.clone(), 0.5), "batch_ms_p95": pct(&mut lat.clone(), 0.95), "batch_ms_p99": pct(&mut lat, 0.99) },
        "edge_decisions": { "decisions": decisions, "devices": ips.len(), "rules": 50, "decisions_per_sec": edge_dps.round(), "blocked": blocked,
                            "us_p50": pct(&mut dl.clone(), 0.5), "us_p99": pct(&mut dl, 0.99) },
        "control_plane_decide": { "requests": 300, "ms_p50": pct(&mut cl.clone(), 0.5), "ms_p95": pct(&mut cl.clone(), 0.95), "ms_p99": pct(&mut cl, 0.99) },
    });
    println!("LOAD-RESULT {}", serde_json::to_string_pretty(&out).unwrap());
    assert!(assets as usize >= total_obs * 9 / 10, "assets {assets} for {total_obs} observations");
}
