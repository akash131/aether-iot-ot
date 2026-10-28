//! Platform API client (docs/integration.md §4–§8a; ZTE-IOT-*-i4 explicit
//! timeouts and backpressure, section 121 SRE dependency isolation).
//!
//! Every call has a connect timeout, an operation timeout and a bounded
//! retry budget with exponential back-off and jitter. Only failures that
//! are safe to retry are retried: transport errors before the request was
//! sent, 429 (honouring `Retry-After`) and 502/503/504 — the latter only
//! for idempotent calls. A small circuit breaker fails fast after repeated
//! consecutive failures so callers degrade quickly instead of piling up.
//! Service tokens (client credentials, tenant-scoped, 15 min) are cached
//! per tenant and refreshed a minute before expiry.

use crate::config::PlatformConfig;
use aether_core::policy::compile::CompiledPolicy;
use aether_core::policy::Context;
use reqwest::Method;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum PlatformError {
    /// The platform answered with an error status.
    Status {
        status: u16,
        code: String,
        detail: String,
    },
    /// Network failure, timeout or open circuit.
    Transport(String),
    Decode(String),
    NotConfigured(&'static str),
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformError::Status { status, code, detail } => write!(f, "platform returned {status} {code}: {detail}"),
            PlatformError::Transport(e) => write!(f, "platform unreachable: {e}"),
            PlatformError::Decode(e) => write!(f, "unexpected platform response: {e}"),
            PlatformError::NotConfigured(what) => write!(f, "{what} is not configured"),
        }
    }
}

impl std::error::Error for PlatformError {}

impl PlatformError {
    pub fn status(&self) -> Option<u16> {
        match self {
            PlatformError::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

pub type PResult<T> = Result<T, PlatformError>;

pub use iot_core::resilience::RetryPolicy;
use iot_core::resilience::{Breaker, DependencyHealth, RetryBudget, Retryability};

const BREAKER_THRESHOLD: u32 = 8;
const BREAKER_OPEN: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Platform {
    inner: Arc<Inner>,
}

struct Inner {
    base: String,
    http: reqwest::Client,
    creds: Option<(String, String)>,
    retry: RetryPolicy,
    budget: RetryBudget,
    breaker: Breaker,
    tokens: Mutex<HashMap<Uuid, (String, Instant)>>,
}

/// Map an error response (RFC 9457 or OAuth) to a typed error.
async fn status_error(res: reqwest::Response) -> PlatformError {
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    let code = body.get("code").or_else(|| body.get("error")).and_then(|v| v.as_str()).unwrap_or("error").to_string();
    let detail = body.get("detail").or_else(|| body.get("error_description")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    PlatformError::Status { status, code, detail }
}

impl Platform {
    pub fn new(cfg: &PlatformConfig) -> anyhow::Result<Platform> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("aether-iot/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(15))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()?;
        let creds = cfg.client_id.clone().zip(cfg.client_secret.clone());
        Ok(Platform {
            inner: Arc::new(Inner {
                base: cfg.url.trim_end_matches('/').to_string(),
                http,
                creds,
                retry: RetryPolicy::default(),
                budget: RetryBudget::default(),
                breaker: Breaker::new(BREAKER_THRESHOLD, BREAKER_OPEN),
                tokens: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn base(&self) -> &str {
        &self.inner.base
    }

    pub fn has_service_credentials(&self) -> bool {
        self.inner.creds.is_some()
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            format!("{}{path}", self.inner.base)
        }
    }

    /// Send with retries. `idempotent` allows retrying gateway errors and
    /// timeouts after the request may have reached the server; requests that
    /// never reached it are always retried. Retries are limited by the
    /// retry budget; the circuit breaker fails fast while the platform keeps
    /// failing. The caller's trace context is propagated (`traceparent`).
    pub async fn send(&self, method: Method, path: &str, token: Option<&str>, body: Option<&Value>, headers: &[(&str, String)], idempotent: bool) -> PResult<reqwest::Response> {
        if !self.inner.breaker.allow() {
            return Err(PlatformError::Transport("circuit open after repeated failures".into()));
        }
        let url = self.url(path);
        let trace = crate::telemetry::current_trace().child();
        self.inner.budget.deposit();
        let mut attempt = 0;
        loop {
            let mut rb = self.inner.http.request(method.clone(), &url).header("traceparent", trace.header());
            if let Some(t) = token {
                rb = rb.bearer_auth(t);
            }
            for (k, v) in headers {
                rb = rb.header(*k, v);
            }
            if let Some(b) = body {
                rb = rb.json(b);
            }
            let last = attempt + 1 >= self.inner.retry.attempts;
            let (class, outcome) = match rb.send().await {
                Ok(res) => (Retryability::from_status(res.status().as_u16()), Ok(res)),
                Err(e) if e.is_connect() => (Retryability::RetryableBeforeSend, Err(e)),
                Err(e) if e.is_timeout() => (Retryability::RetryableIfIdempotent, Err(e)),
                Err(e) => (Retryability::Failed, Err(e)),
            };
            if class.may_retry(idempotent) && !last && self.inner.budget.withdraw() {
                let wait = match &outcome {
                    Ok(res) => res.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).map(Duration::from_secs),
                    Err(_) => None,
                }
                .unwrap_or_else(|| self.inner.retry.delay(attempt))
                .min(self.inner.retry.max_delay);
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }
            if class.is_dependency_failure() {
                self.inner.breaker.failure();
            } else {
                self.inner.breaker.success();
            }
            return outcome.map_err(|e| PlatformError::Transport(e.without_url().to_string()));
        }
    }

    /// Breaker and retry-budget state (health endpoints, heartbeats).
    pub fn health(&self) -> DependencyHealth {
        DependencyHealth { name: "platform".into(), breaker: self.inner.breaker.state(), trips: self.inner.breaker.trips(), retry_budget: self.inner.budget.available() }
    }

    /// JSON call returning the decoded body of a 2xx response.
    pub async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<&Value>) -> PResult<Value> {
        let idempotent = matches!(method, Method::GET | Method::PUT | Method::DELETE | Method::HEAD);
        let res = self.send(method, path, token, body, &[], idempotent).await?;
        if !res.status().is_success() {
            return Err(status_error(res).await);
        }
        res.json::<Value>().await.map_err(|e| PlatformError::Decode(e.to_string()))
    }

    pub async fn get(&self, path: &str, token: &str) -> PResult<Value> {
        self.call(Method::GET, path, Some(token), None).await
    }

    /// Tenant-scoped (or operator-plane, `None`) service token.
    pub async fn service_token(&self, tenant: Option<Uuid>) -> PResult<String> {
        let (id, secret) = self.inner.creds.clone().ok_or(PlatformError::NotConfigured("service client credentials (IOT_CLIENT_ID/IOT_CLIENT_SECRET)"))?;
        let key = tenant.unwrap_or(Uuid::nil());
        if let Some((t, exp)) = self.inner.tokens.lock().await.get(&key) {
            if *exp > Instant::now() + Duration::from_secs(60) {
                return Ok(t.clone());
            }
        }
        let mut body = json!({ "grant_type": "client_credentials", "client_id": id, "client_secret": secret });
        if let Some(t) = tenant {
            body["tenant_id"] = json!(t);
        }
        let v = self.call(Method::POST, "/api/v1/oauth/token", None, Some(&body)).await?;
        let token = v["access_token"].as_str().ok_or_else(|| PlatformError::Decode("no access_token".into()))?.to_string();
        let ttl = v["expires_in"].as_i64().unwrap_or(900).clamp(60, 3600) as u64;
        self.inner.tokens.lock().await.insert(key, (token.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(token)
    }

    /// Drop a cached token after the platform rejected it.
    pub async fn forget_token(&self, tenant: Option<Uuid>) {
        self.inner.tokens.lock().await.remove(&tenant.unwrap_or(Uuid::nil()));
    }

    pub fn configured(&self) -> bool {
        self.inner.creds.is_some()
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.inner.http
    }

    /// Register the product's policy types, the `firewall.network`
    /// extension, action owners and log schemas (operator-plane token).
    pub async fn register_policy_types(&self) -> PResult<usize> {
        let token = self.service_token(None).await?;
        let mut n = 0;
        for t in iot_core::policy::types() {
            self.call(Method::PUT, &format!("/api/v1/policy-types/{}", t.key), Some(&token), Some(&iot_core::policy::registration(&t))).await?;
            n += 1;
        }
        let ext = serde_json::to_value(iot_core::policy::firewall_extension()).unwrap_or_default();
        if let Err(e) = self.call(Method::PUT, "/api/v1/policy-types/firewall.network/extensions/iot", Some(&token), Some(&ext)).await {
            tracing::warn!(error = %e, "firewall.network extension not registered");
        }
        for (key, actions) in iot_core::policy::action_owners() {
            if let Err(e) = self.call(Method::PUT, &format!("/api/v1/policy-types/{key}/action-owners"), Some(&token), Some(&json!({ "actions": actions }))).await {
                tracing::warn!(error = %e, key, "action owners not declared");
            }
        }
        Ok(n)
    }

    /// Register the typed attributes of this product's log types
    /// (contract 2026-11c §8a).
    pub async fn register_log_schemas(&self) -> PResult<usize> {
        let token = self.service_token(None).await?;
        let mut n = 0;
        for (log_type, fields) in crate::pipeline::log_schemas() {
            self.call(Method::PUT, &format!("/api/v1/log-schemas/{log_type}"), Some(&token), Some(&json!({ "fields": fields }))).await?;
            n += 1;
        }
        Ok(n)
    }

    /// Active compiled policies of the tenant for a type prefix (`iot.`),
    /// verified over the received document.
    pub async fn active_policies(&self, tenant: Uuid, prefix: &str) -> PResult<Vec<CompiledPolicy>> {
        let token = self.service_token(Some(tenant)).await?;
        let sets = self.get("/api/v1/policy-sets?limit=500", &token).await?;
        let mut out = vec![];
        for s in sets["data"].as_array().cloned().unwrap_or_default() {
            let ty = s["policy_type"].as_str().unwrap_or_default();
            let (Some(id), Some(rev)) = (s["id"].as_str(), s["active_revision"].as_i64()) else { continue };
            if !ty.starts_with(prefix) {
                continue;
            }
            let r = self.get(&format!("/api/v1/policy-sets/{id}/revisions/{rev}"), &token).await?;
            let compiled = CompiledPolicy::from_json_verified(r["data"]["compiled"].clone()).map_err(|e| PlatformError::Decode(format!("compiled policy {id}/{rev}: {e}")))?;
            out.push(compiled);
        }
        Ok(out)
    }

    /// Declare service hooks: `iot.*` reference validation and
    /// `iot.segmentation` simulation enrichment.
    pub async fn register_service_hooks(&self) -> PResult<Value> {
        let token = self.service_token(None).await?;
        let body = json!({
            "ref_types": iot_core::policy::REF_TYPES.iter().map(|r| r.0).collect::<Vec<_>>(),
            "simulate_types": [iot_core::policy::SEGMENTATION],
        });
        self.call(Method::PUT, "/api/v1/service-hooks", Some(&token), Some(&body)).await
    }

    /// Ship log events (product log types `iot_*`).
    pub async fn ingest_logs(&self, tenant: Uuid, events: &[Value]) -> PResult<Value> {
        let token = self.service_token(Some(tenant)).await?;
        let res = self.send(Method::POST, "/api/v1/logs/ingest", Some(&token), Some(&Value::Array(events.to_vec())), &[], false).await?;
        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.forget_token(Some(tenant)).await;
        }
        if !res.status().is_success() {
            return Err(status_error(res).await);
        }
        res.json::<Value>().await.map_err(|e| PlatformError::Decode(e.to_string()))
    }

    /// Post risk signals (subject_type workload / device).
    pub async fn post_signals(&self, tenant: Uuid, signals: &[Value]) -> PResult<Value> {
        let token = self.service_token(Some(tenant)).await?;
        self.call(Method::POST, "/api/v1/signals", Some(&token), Some(&Value::Array(signals.to_vec()))).await
    }

    /// Hand a decision to administrators (platform approval inbox).
    pub async fn create_approval(&self, tenant: Uuid, body: &Value) -> PResult<Value> {
        let token = self.service_token(Some(tenant)).await?;
        self.call(Method::POST, "/api/v1/approvals", Some(&token), Some(body)).await
    }

    pub async fn get_approval(&self, tenant: Uuid, id: Uuid) -> PResult<Value> {
        let token = self.service_token(Some(tenant)).await?;
        self.get(&format!("/api/v1/approvals/{id}"), &token).await
    }

    /// Decided approvals since a version cursor.
    pub async fn decided_approvals(&self, tenant: Uuid, since_version: i64) -> PResult<Value> {
        let token = self.service_token(Some(tenant)).await?;
        self.get(&format!("/api/v1/approvals?state=approved,denied,expired&since_version={since_version}&limit=200"), &token).await
    }

    pub async fn cancel_approval(&self, tenant: Uuid, id: Uuid) -> PResult<Value> {
        let token = self.service_token(Some(tenant)).await?;
        self.call(Method::POST, &format!("/api/v1/approvals/{id}/cancel"), Some(&token), Some(&json!({}))).await
    }

    /// Resolve identity, device, location and risk context of a user.
    pub async fn resolve_context(&self, token: &str, user_email: Option<&str>, device_id: Option<&str>, source_ip: Option<&str>) -> PResult<(Context, Option<String>)> {
        let mut q: Vec<String> = vec![];
        let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
        if let Some(e) = user_email {
            q.push(format!("user_email={}", enc(e)));
        }
        if let Some(d) = device_id {
            q.push(format!("device_id={}", enc(d)));
        }
        if let Some(ip) = source_ip {
            q.push(format!("source_ip={}", enc(ip)));
        }
        let v = self.get(&format!("/api/v1/context/resolve?{}", q.join("&")), token).await?;
        let ctx: Context = serde_json::from_value(v["data"]["context"].clone()).map_err(|e| PlatformError::Decode(e.to_string()))?;
        Ok((ctx, v["data"]["user_status"].as_str().map(|s| s.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        let p = RetryPolicy::default();
        assert!(p.delay(0) >= Duration::from_millis(200) && p.delay(0) <= Duration::from_millis(400));
        assert!(p.delay(2) >= Duration::from_millis(800));
        assert_eq!(p.delay(30), Duration::from_secs(5));
    }

    #[test]
    fn breaker_opens_after_threshold() {
        let b = Breaker::new(BREAKER_THRESHOLD, BREAKER_OPEN);
        for _ in 0..BREAKER_THRESHOLD - 1 {
            b.failure();
        }
        assert!(b.allow());
        b.success();
        for _ in 0..BREAKER_THRESHOLD {
            b.failure();
        }
        assert!(!b.allow());
    }

    #[tokio::test]
    async fn unreachable_platform_is_a_transport_error() {
        let p = Platform::new(&PlatformConfig { url: "http://127.0.0.1:1".into(), issuer: "x".into(), audience: "aether".into(), client_id: None, client_secret: None }).unwrap();
        let e = p.call(Method::GET, "/api/v1/x", None, None).await.unwrap_err();
        assert!(matches!(e, PlatformError::Transport(_)), "{e}");
        assert!(matches!(p.service_token(None).await, Err(PlatformError::NotConfigured(_))));
    }
}
