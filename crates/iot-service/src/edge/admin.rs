//! Edge local API: health, metrics, status, the flow decision API for
//! local enforcement points and safe operator actions.
//!
//! | Route | Auth | Purpose |
//! |---|---|---|
//! | `GET /health/live` | – | liveness |
//! | `GET /health/ready` | – | 200 once a verified configuration is loaded |
//! | `GET /metrics` | – | Prometheus metrics |
//! | `GET /status` | token | configuration, capture, queue, health, failure modes |
//! | `POST /v1/decide` | token | decide a flow `{src_ip, dst_ip, protocol?, operation_class?, port?}` |
//! | `GET /v1/nftables` | token | the rendered host enforcement rules |
//! | `POST /actions/resync` | token | poll configuration now |
//! | `POST /actions/flush` | token | ship queued observations now |
//!
//! The token is `IOT_EDGE_ADMIN_TOKEN` (constant-time comparison); without
//! it protected routes answer 403.

use super::Agent;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

fn authorized(agent: &Agent, headers: &HeaderMap) -> Result<(), Response> {
    let Some(expected) = agent.cfg.admin_token.as_deref() else {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": "the edge admin API is disabled (IOT_EDGE_ADMIN_TOKEN is not set)" }))).into_response());
    };
    let given = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if aether_kit::crypto::constant_time_eq(given.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid admin token" }))).into_response())
    }
}

async fn ready(State(a): State<Arc<Agent>>) -> Response {
    let rt = a.runtime();
    let loaded = !rt.snapshot.is_null();
    let body = Json(
        json!({ "node_id": a.node_id, "config_version": rt.config_version, "revision": rt.revision, "policy_loaded": rt.policy.is_some(), "config_age_secs": a.config_age_secs() }),
    );
    if loaded {
        (StatusCode::OK, body).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, body).into_response()
    }
}

async fn status(State(a): State<Arc<Agent>>, h: HeaderMap) -> Response {
    if let Err(r) = authorized(&a, &h) {
        return r;
    }
    Json(a.status()).into_response()
}

#[derive(Deserialize)]
struct DecideReq {
    src_ip: String,
    dst_ip: String,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    operation_class: Option<String>,
    #[serde(default)]
    port: Option<u16>,
}

async fn decide(State(a): State<Arc<Agent>>, h: HeaderMap, Json(r): Json<DecideReq>) -> Response {
    if let Err(resp) = authorized(&a, &h) {
        return resp;
    }
    if r.src_ip.parse::<std::net::IpAddr>().is_err() || r.dst_ip.parse::<std::net::IpAddr>().is_err() {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "error": "src_ip and dst_ip must be IP addresses" }))).into_response();
    }
    let rt = a.runtime();
    let started = std::time::Instant::now();
    let v = rt.decide(&r.src_ip, &r.dst_ip, r.protocol.as_deref(), r.operation_class.as_deref(), r.port, Utc::now());
    a.decisions.record(&v, &rt.device(&r.src_ip), &rt.device(&r.dst_ip), r.protocol.as_deref(), r.operation_class.as_deref());
    a.metrics.count("decision", &v.enforced);
    Json(json!({ "verdict": v, "config_version": rt.config_version, "revision": rt.revision, "latency_us": started.elapsed().as_micros() as u64 })).into_response()
}

async fn nftables(State(a): State<Arc<Agent>>, h: HeaderMap) -> Response {
    if let Err(r) = authorized(&a, &h) {
        return r;
    }
    a.nft.lock().unwrap_or_else(|e| e.into_inner()).clone().into_response()
}

async fn action(State(a): State<Arc<Agent>>, h: HeaderMap, axum::extract::Path(name): axum::extract::Path<String>) -> Response {
    if let Err(r) = authorized(&a, &h) {
        return r;
    }
    let result = match name.as_str() {
        "resync" => {
            a.sync_now.notify_one();
            json!({ "requested": true })
        }
        "flush" => match a.flush().await {
            Ok(n) => json!({ "shipped_batches": n }),
            Err(e) => json!({ "error": e.to_string() }),
        },
        _ => return (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown action" }))).into_response(),
    };
    tracing::info!(action = %name, result = %result, "edge admin action");
    Json(json!({ "action": name, "result": result })).into_response()
}

pub fn router(agent: Arc<Agent>) -> Router {
    let m = agent.clone();
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(ready))
        .route("/metrics", get(move || async move { m.metrics.render() }))
        .route("/status", get(status))
        .route("/v1/decide", post(decide))
        .route("/v1/nftables", get(nftables))
        .route("/actions/{name}", post(action))
        .with_state(agent)
}

pub async fn serve_admin(agent: Arc<Agent>, bind: String) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "edge local API");
    axum::serve(listener, router(agent)).await?;
    Ok(())
}
