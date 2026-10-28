//! Test harness: the service on an ephemeral port against PostgreSQL
//! (`IOT_TEST_DATABASE_URL`, a non-superuser role so RLS is effective) with
//! locally signed platform tokens and in-process fakes of the peer
//! products. Traffic is synthesised with the packet builders and run
//! through the real collector, exactly as an edge would.
#![allow(dead_code)]

use aether_kit::auth::{AccessClaims, Verifier};
use aether_kit::ActorType;
use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use iot_core::collect::Collector;
use iot_core::packet::{build, Mac};
use iot_service::config::{PlatformConfig, ServeConfig};
use iot_service::integrations::{Branch, BranchDevice, BrokerSession, Firewall, Grant, PrivateAccess};
use iot_service::platform::PResult;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub use reqwest::Method;

pub const ISSUER: &str = "https://platform.test";
pub const ALL: &[&str] =
    &["policy.iot:read", "policy.iot:create", "policy.iot:update", "policy.iot:delete", "policy.iot:activate", "changes:approve", "logs:read", "audit:export", "status:read"];

/// Calls seen by the peer fakes: (peer, operation, detail).
pub type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

pub struct FakeBranch(pub Seen, pub Vec<BranchDevice>);
pub struct FakeAccess(pub Seen);
pub struct FakeFirewall(pub Seen);

#[async_trait]
impl Branch for FakeBranch {
    fn name(&self) -> &'static str {
        "fake_branch"
    }
    fn configured(&self) -> bool {
        true
    }
    async fn devices(&self, _: Uuid, cursor: Option<String>) -> PResult<(Vec<BranchDevice>, Option<String>)> {
        self.0.lock().unwrap().push(("branch".into(), "devices".into(), json!(cursor)));
        Ok((if cursor.is_none() { self.1.clone() } else { vec![] }, None))
    }
}

#[async_trait]
impl PrivateAccess for FakeAccess {
    fn name(&self) -> &'static str {
        "fake_private_access"
    }
    fn configured(&self) -> bool {
        true
    }
    async fn grant(&self, _: Uuid, email: &str, console: &str, start: DateTime<Utc>, end: DateTime<Utc>, reason: &str) -> PResult<Grant> {
        self.0.lock().unwrap().push(("pa".into(), "grant".into(), json!({ "email": email, "console": console, "start": start, "end": end, "reason": reason })));
        Ok(Grant { source: "private_access".into(), reference: format!("pa-{}", Uuid::now_v7()) })
    }
    async fn revoke(&self, _: Uuid, g: &Grant) -> PResult<()> {
        self.0.lock().unwrap().push(("pa".into(), "revoke".into(), json!(g.reference)));
        Ok(())
    }
    async fn sessions(&self, _: Uuid, console: &str) -> PResult<Vec<BrokerSession>> {
        self.0.lock().unwrap().push(("pa".into(), "sessions".into(), json!(console)));
        Ok(vec![])
    }
    async fn terminate(&self, _: Uuid, id: &str) -> PResult<()> {
        self.0.lock().unwrap().push(("pa".into(), "terminate".into(), json!(id)));
        Ok(())
    }
}

#[async_trait]
impl Firewall for FakeFirewall {
    fn name(&self) -> &'static str {
        "fake_firewall"
    }
    fn configured(&self) -> bool {
        true
    }
    async fn bind(&self, _: Uuid, b: &[(String, Uuid)]) -> PResult<usize> {
        self.0.lock().unwrap().push(("firewall".into(), "bind".into(), json!(b.iter().map(|(a, d)| json!({ "address": a, "device_id": d })).collect::<Vec<_>>())));
        Ok(b.len())
    }
}

pub struct Harness {
    pub base: String,
    pub http: reqwest::Client,
    pub key: EncodingKey,
    pub pool: sqlx::PgPool,
    pub state: iot_service::state::AppState,
    pub seen: Seen,
}

pub fn db_url() -> Option<String> {
    std::env::var("IOT_TEST_DATABASE_URL").ok().filter(|s| !s.is_empty())
}

impl Harness {
    pub async fn start() -> Option<Harness> {
        Self::start_with(|c| c, false).await
    }

    /// With in-process fakes of branch, private access and firewall.
    pub async fn with_peers() -> Option<Harness> {
        Self::start_with(|c| c, true).await
    }

    pub async fn start_with(f: impl FnOnce(ServeConfig) -> ServeConfig, peers: bool) -> Option<Harness> {
        let Some(url) = db_url() else {
            eprintln!("skipping API tests (set IOT_TEST_DATABASE_URL)");
            return None;
        };
        static TRACING: std::sync::Once = std::sync::Once::new();
        TRACING.call_once(|| {
            if std::env::var("IOT_LOG").is_ok() {
                aether_kit::telemetry::init_tracing(false, "IOT_LOG");
            }
        });
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp.public_key().as_ref());
        let jwks = serde_json::from_value(json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": "test", "alg": "EdDSA", "use": "sig" }] })).unwrap();
        let verifier = Verifier::with_keys(ISSUER, "aether", jwks);
        let pool = aether_kit::db::connect(&url, 10, "iot-api-test").await.unwrap();
        iot_service::migrate(&pool).await.unwrap();
        aether_kit::db::assert_rls_effective(&pool, true).await.expect("test role must not bypass RLS");
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let platform = PlatformConfig { url: "http://127.0.0.1:1".into(), issuer: ISSUER.into(), audience: "aether".into(), client_id: None, client_secret: None };
        let mut cfg = ServeConfig::for_tests(&url, platform);
        cfg.bind = addr.to_string();
        cfg.public_url = format!("http://{addr}");
        let cfg = f(cfg);
        let seen: Seen = Arc::default();
        let mut state = iot_service::state::AppState::with_verifier(pool.clone(), cfg, verifier).unwrap();
        if peers {
            let devices = vec![BranchDevice {
                mac: "02:bb:00:00:00:01".into(),
                ip: Some("10.77.0.5".into()),
                hostname: Some("lobby-cam".into()),
                vendor: Some("Axis".into()),
                os: None,
                class: Some("camera".into()),
                confidence: Some(0.9),
                site_id: None,
                last_seen: Some(Utc::now()),
            }];
            state = state.with_peers(Arc::new(FakeBranch(seen.clone(), devices)), Arc::new(FakeAccess(seen.clone())), Arc::new(FakeFirewall(seen.clone())));
        }
        let s2 = state.clone();
        tokio::spawn(async move { axum::serve(l, iot_service::api::router(s2).into_make_service_with_connect_info::<SocketAddr>()).await });
        Some(Harness {
            base: format!("http://{addr}"),
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            key: EncodingKey::from_ed_der(doc.as_ref()),
            pool,
            state,
            seen,
        })
    }

    pub fn token(&self, tenant: Uuid, act: ActorType, perms: &[&str], ent: &[&str]) -> String {
        self.token_for(tenant, Uuid::now_v7(), act, perms, ent)
    }

    pub fn token_for(&self, tenant: Uuid, sub: Uuid, act: ActorType, perms: &[&str], ent: &[&str]) -> String {
        let now = Utc::now().timestamp();
        let c = AccessClaims {
            iss: ISSUER.into(),
            aud: "aether".into(),
            sub,
            tid: tenant,
            typ: "access".into(),
            act,
            name: format!("tester-{sub}@example.com"),
            sid: None,
            cid: None,
            perms: perms.iter().map(|s| s.to_string()).collect(),
            scope: aether_core::rbac::AdminScope::Organization,
            mfa: true,
            ent: ent.iter().map(|s| s.to_string()).collect(),
            iat: now,
            exp: now + 600,
            jti: Uuid::new_v4(),
        };
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("test".into());
        encode(&h, &c, &self.key).unwrap()
    }

    /// A node access token (`act=node`) with the node kind claim.
    pub fn node_token(&self, tenant: Uuid, node: Uuid, kind: &str) -> String {
        let now = Utc::now().timestamp();
        let c = AccessClaims {
            iss: ISSUER.into(),
            aud: "aether".into(),
            sub: node,
            tid: tenant,
            typ: "access".into(),
            act: ActorType::Node,
            name: format!("node-{node}"),
            sid: None,
            cid: None,
            perms: vec![],
            scope: aether_core::rbac::AdminScope::Organization,
            mfa: false,
            ent: vec!["iot".into()],
            iat: now,
            exp: now + 600,
            jti: Uuid::new_v4(),
        };
        let mut v = serde_json::to_value(&c).unwrap();
        v["nk"] = json!(kind);
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("test".into());
        encode(&h, &v, &self.key).unwrap()
    }

    pub fn admin(&self, tenant: Uuid) -> String {
        self.token(tenant, ActorType::Admin, ALL, &["iot"])
    }

    pub async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>, headers: &[(&str, &str)]) -> (u16, Value, reqwest::header::HeaderMap) {
        let url = if path.starts_with("http") { path.to_string() } else { format!("{}{path}", self.base) };
        let mut rb = self.http.request(method, url);
        if let Some(t) = token {
            rb = rb.bearer_auth(t);
        }
        for (k, v) in headers {
            rb = rb.header(*k, *v);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let s = r.status().as_u16();
        let h = r.headers().clone();
        let t = r.text().await.unwrap();
        (s, serde_json::from_str(&t).unwrap_or(Value::String(t)), h)
    }

    pub async fn post(&self, path: &str, token: &str, body: Value) -> Value {
        let (s, v, _) = self.call(Method::POST, path, Some(token), Some(body), &[]).await;
        assert!(s == 201 || s == 200 || s == 202, "POST {path}: {s} {v}");
        v["data"].clone()
    }

    pub async fn put(&self, path: &str, token: &str, body: Value) -> Value {
        let (s, v, _) = self.call(Method::PUT, path, Some(token), Some(body), &[]).await;
        assert!(s == 201 || s == 200, "PUT {path}: {s} {v}");
        v["data"].clone()
    }

    pub async fn get(&self, path: &str, token: &str) -> Value {
        let (s, v, _) = self.call(Method::GET, path, Some(token), None, &[]).await;
        assert_eq!(s, 200, "GET {path}: {v}");
        v
    }

    pub async fn patch(&self, path: &str, token: &str, version: i64, body: Value) -> Value {
        let etag = format!("\"v{version}\"");
        let (s, v, _) = self.call(Method::PATCH, path, Some(token), Some(body), &[("if-match", &etag)]).await;
        assert_eq!(s, 200, "PATCH {path}: {v}");
        v["data"].clone()
    }

    pub async fn count(&self, table: &str, tenant: Uuid) -> i64 {
        let mut tx = aether_kit::db::tenant_tx(&self.pool, tenant).await.unwrap();
        let (n,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM {table} WHERE tenant_id = $1")).bind(tenant).fetch_one(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        n
    }

    pub async fn scalar(&self, tenant: Uuid, sql: &str) -> Value {
        let mut tx = aether_kit::db::tenant_tx(&self.pool, tenant).await.unwrap();
        let (v,): (Value,) = sqlx::query_as(sql).fetch_one(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        v
    }

    /// Site + sensor bound to a fresh node; returns (site, sensor, node, node token).
    pub async fn site_and_sensor(&self, tenant: Uuid) -> (String, String, Uuid, String) {
        let tok = self.admin(tenant);
        let site = self.post("/api/v1/sites", &tok, json!({ "name": format!("Plant {}", &Uuid::new_v4().simple().to_string()[..12]), "region": "eu", "criticality": 4 })).await;
        let node = Uuid::now_v7();
        let sensor = self.post("/api/v1/sensors", &tok, json!({ "name": format!("edge-{}", &node.simple().to_string()[20..]), "site_id": site["id"], "kind": "edge_appliance", "node_id": node.to_string(), "enforcement": true })).await;
        (site["id"].as_str().unwrap().into(), sensor["id"].as_str().unwrap().into(), node, self.node_token(tenant, node, "service_edge"))
    }

    /// Ship observations as the edge would.
    pub async fn observe(&self, node_token: &str, obs: Vec<iot_core::model::Observation>) -> Value {
        let (s, v, _) =
            self.call(Method::POST, "/api/v1/node/observations", Some(node_token), Some(json!({ "batch_id": Uuid::now_v7().to_string(), "observations": obs })), &[]).await;
        assert!(s == 202 || s == 200, "observations: {s} {v}");
        v["data"].clone()
    }

    pub async fn asset_by_ip(&self, tok: &str, ip: &str) -> Value {
        let v = self.get(&format!("/api/v1/assets?ip={ip}"), tok).await;
        v["data"].as_array().and_then(|a| a.first().cloned()).unwrap_or_else(|| {
            panic!("no asset for {ip}: {v}");
        })
    }
}

pub fn mac(last: u8) -> Mac {
    Mac([0x00, 0x80, 0xf4, 0x10, 0x00, last])
}

/// A small OT cell: an engineering workstation writing to a PLC (Modbus),
/// an HMI reading it and telnet to the PLC, as raw Ethernet frames
/// `(timestamp µs, frame)` — what a span port delivers.
pub fn ot_frames(base: u8) -> Vec<(i64, Vec<u8>)> {
    let mut out = vec![];
    let ip = |h: u8| Ipv4Addr::new(10, base, 0, h);
    let plc = (Mac([0x00, 0x80, 0xf4, base, 0, 10]), ip(10), 502u16);
    let hmi = (Mac([0x00, 0x0e, 0x8c, base, 0, 20]), ip(20), 49152u16);
    let ews = (Mac([0x00, 0x1b, 0x21, base, 0, 30]), ip(30), 49153u16);
    let t0 = Utc::now().timestamp_micros();
    // HMI reads holding registers; the PLC answers.
    for i in 0..5u16 {
        let req = iot_core::protocols::modbus::adu(i, 1, &[3, 0, 0, 0, 10]);
        out.push((t0 + i as i64, build::tcp_frame(hmi, plc, 0x18, &req)));
        let resp = iot_core::protocols::modbus::adu(i, 1, &[3, 20, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10]);
        out.push((t0 + i as i64 + 1, build::tcp_frame(plc, hmi, 0x18, &resp)));
    }
    // Device identification answer exposes vendor/product/firmware.
    let mut pdu = vec![43, 14, 1, 0x81, 0, 0, 3];
    for (id, s) in [(0u8, "Schneider Electric"), (1, "M580 BMEP582040"), (2, "v2.4")] {
        pdu.push(id);
        pdu.push(s.len() as u8);
        pdu.extend_from_slice(s.as_bytes());
    }
    out.push((t0 + 20, build::tcp_frame(plc, hmi, 0x18, &iot_core::protocols::modbus::adu(9, 1, &pdu))));
    // Engineering workstation writes a register.
    out.push((t0 + 30, build::tcp_frame(ews, plc, 0x18, &iot_core::protocols::modbus::adu(77, 1, &[6, 0, 1, 0, 42]))));
    // Telnet to the PLC (insecure protocol).
    out.push((t0 + 40, build::tcp_frame(ews, (plc.0, plc.1, 23), 0x02, &[])));
    out.push((t0 + 41, build::tcp_frame((plc.0, plc.1, 23), ews, 0x12, &[])));
    out
}

/// The OT cell as observations from the real collector.
pub fn ot_cell(base: u8) -> Vec<iot_core::model::Observation> {
    let mut c = Collector::default();
    for (ts, f) in ot_frames(base) {
        c.ingest(ts, &f);
    }
    c.drain(None, None)
}
