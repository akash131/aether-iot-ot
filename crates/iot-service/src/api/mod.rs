//! HTTP surface of the IoT/OT Security service (ZTE-IOT sections 106 IoT/OT
//! Apis, 107–109, 116 Platform Security; Volume 2 API dimension rows).
//!
//! `/api/v1/...` with aether-kit envelopes, RFC 9457 problems, `If-Match`,
//! `Idempotency-Key`, cursor pagination, audit and outbox on every
//! mutation; `/api/v1/meta/resources` describes every resource, write-only
//! input, item action, dashboard and wizard for the platform console
//! (sections 98–104 screens are rendered by the console from this
//! metadata).

pub mod assets;
pub mod common;
pub mod findings;
pub mod hooks;
pub mod ingest;
pub mod ops;
pub mod remote;
pub mod resources;
pub mod segmentation;

use crate::state::{AppState, ACTIVATE, CREATE, LABEL, PRODUCT, READ, UPDATE};
use aether_kit::http::middleware;
use aether_kit::resource::{meta_routes_full, MetaAction, MetaDashboard, MetaExtra, MetaWizard};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

const fn a(name: &'static str, label: &'static str, path: &'static str, permission: &'static str, confirm: bool, body: Option<&'static str>) -> MetaAction {
    MetaAction { name, label, method: "POST", path, permission, confirm, body }
}

/// Console metadata: item actions per resource.
pub static META: &[MetaExtra] = &[
    MetaExtra {
        resource: "exceptions",
        write_only: &[],
        actions: &[a("approve", "Approve", "approve", ACTIVATE, true, None), a("deny", "Deny", "deny", ACTIVATE, true, None), a("revoke", "Revoke", "revoke", UPDATE, true, None)],
    },
    MetaExtra {
        resource: "rollouts",
        write_only: &[],
        actions: &[
            a("start", "Start", "start", ACTIVATE, true, None),
            a("advance", "Advance to next stage", "advance", ACTIVATE, true, None),
            a("rollback", "Roll back", "rollback", ACTIVATE, true, None),
        ],
    },
    MetaExtra { resource: "assertions", write_only: &[], actions: &[] },
    MetaExtra {
        resource: "investigations",
        write_only: &[],
        actions: &[a(
            "add_evidence",
            "Add evidence",
            "evidence",
            UPDATE,
            false,
            Some(r#"{"kind":"asset_snapshot|anomaly|flows|note|observation|decision|file_digest","ref":"uuid","data":"object"}"#),
        )],
    },
];

/// Dashboards rendered by the platform console (sections 98, 101, 102).
pub static DASHBOARDS: &[MetaDashboard] = &[
    MetaDashboard {
        name: "overview",
        label: "IoT/OT overview",
        permission: READ,
        widgets: r#"[
            {"kind": "kpi", "title": "Devices", "endpoint": "/api/v1/dashboards/overview", "value": "data.assets"},
            {"kind": "kpi", "title": "OT devices", "endpoint": "/api/v1/dashboards/overview", "value": "data.ot_assets"},
            {"kind": "kpi", "title": "New in 24 h", "endpoint": "/api/v1/dashboards/overview", "value": "data.new_last_24h"},
            {"kind": "kpi", "title": "High and critical risk", "endpoint": "/api/v1/dashboards/overview", "value": "data.high_risk"},
            {"kind": "kpi", "title": "Open anomalies", "endpoint": "/api/v1/dashboards/overview", "value": "data.open_anomalies"},
            {"kind": "kpi", "title": "Sensors offline", "endpoint": "/api/v1/dashboards/overview", "value": "data.sensors_offline"},
            {"kind": "table", "title": "Highest priority devices", "endpoint": "/api/v1/dashboards/overview", "rows": "data.top_risk", "columns": [{"key": "name", "label": "Device"}, {"key": "device_type", "label": "Type"}, {"key": "risk_score", "label": "Risk"}, {"key": "priority", "label": "Priority"}]},
            {"kind": "list", "title": "Recent anomalies", "endpoint": "/api/v1/dashboards/overview", "rows": "data.recent_anomalies", "label": "title", "detail": "kind"}
        ]"#,
    },
    MetaDashboard {
        name: "risk",
        label: "Device risk",
        permission: READ,
        widgets: r#"[
            {"kind": "kpi", "title": "Known exploited", "endpoint": "/api/v1/dashboards/risk", "value": "data.known_exploited"},
            {"kind": "kpi", "title": "End of life", "endpoint": "/api/v1/dashboards/risk", "value": "data.end_of_life"},
            {"kind": "table", "title": "Remediation priority", "endpoint": "/api/v1/dashboards/risk", "rows": "data.priority_queue", "columns": [{"key": "name", "label": "Device"}, {"key": "risk_score", "label": "Risk"}, {"key": "impact", "label": "Impact"}, {"key": "priority", "label": "Priority"}]}
        ]"#,
    },
    MetaDashboard {
        name: "ot-activity",
        label: "OT activity",
        permission: READ,
        widgets: r#"[
            {"kind": "kpi", "title": "Modifying flows (24 h)", "endpoint": "/api/v1/dashboards/ot-activity", "value": "data.modifying_flows"},
            {"kind": "kpi", "title": "Engineering operations (7 d)", "endpoint": "/api/v1/dashboards/ot-activity", "value": "data.engineering_operations"},
            {"kind": "kpi", "title": "Parser errors (24 h)", "endpoint": "/api/v1/dashboards/ot-activity", "value": "data.parser_errors"}
        ]"#,
    },
    MetaDashboard {
        name: "remote-access",
        label: "OT remote access",
        permission: READ,
        widgets: r#"[
            {"kind": "kpi", "title": "Pending approvals", "endpoint": "/api/v1/dashboards/remote-access", "value": "data.pending"},
            {"kind": "kpi", "title": "Active sessions", "endpoint": "/api/v1/dashboards/remote-access", "value": "data.active_sessions"},
            {"kind": "kpi", "title": "Vendors expiring in 14 days", "endpoint": "/api/v1/dashboards/remote-access", "value": "data.vendors_expiring"},
            {"kind": "table", "title": "Recent requests", "endpoint": "/api/v1/dashboards/remote-access", "rows": "data.recent", "columns": [{"key": "requester_email", "label": "Requester"}, {"key": "state", "label": "State"}, {"key": "window_start", "label": "From"}, {"key": "window_end", "label": "Until"}]}
        ]"#,
    },
];

/// Wizards rendered by the platform console (sections 3, 86–87, 102).
pub static WIZARDS: &[MetaWizard] = &[
    MetaWizard {
        name: "add-site",
        label: "Add a site",
        permission: CREATE,
        steps: r#"[{"title": "Site", "fields": [{"name": "name", "label": "Name", "type": "text", "required": true}, {"name": "region", "label": "Region", "type": "text"}, {"name": "criticality", "label": "Criticality (1-5)", "type": "number"}, {"name": "timezone", "label": "Time zone", "type": "text"}]}]"#,
        submit_method: "POST",
        submit_path: "/api/v1/sites",
    },
    MetaWizard {
        name: "request-remote-access",
        label: "Request OT remote access",
        permission: CREATE,
        steps: r#"[{"title": "Target and window", "fields": [{"name": "target_id", "label": "Remote target", "type": "text", "required": true}, {"name": "protocol", "label": "Protocol", "type": "enum", "values": ["https", "rdp", "ssh", "vnc"], "required": true}, {"name": "window_start", "label": "Start (RFC 3339)", "type": "text", "required": true}, {"name": "window_end", "label": "End (RFC 3339)", "type": "text", "required": true}]},
                   {"title": "Justification", "fields": [{"name": "vendor_principal_id", "label": "Vendor principal", "type": "text"}, {"name": "justification", "label": "Justification", "type": "textarea", "required": true}, {"name": "ticket", "label": "Work order", "type": "text"}]}]"#,
        submit_method: "POST",
        submit_path: "/api/v1/access-requests",
    },
    MetaWizard {
        name: "segmentation-exception",
        label: "Request a segmentation exception",
        permission: CREATE,
        steps: r#"[{"title": "Communication", "fields": [{"name": "name", "label": "Name", "type": "text", "required": true}, {"name": "source_asset_id", "label": "Source device", "type": "text"}, {"name": "destination_asset_id", "label": "Destination device", "type": "text"}, {"name": "protocol", "label": "Protocol", "type": "text"}, {"name": "port", "label": "Port", "type": "number"}, {"name": "max_op", "label": "Highest operation", "type": "enum", "values": ["read", "write", "control", "program"]}]},
                   {"title": "Window and reason", "fields": [{"name": "starts_at", "label": "Start (RFC 3339)", "type": "text", "required": true}, {"name": "expires_at", "label": "Expiry (RFC 3339)", "type": "text", "required": true}, {"name": "justification", "label": "Justification", "type": "textarea", "required": true}]}]"#,
        submit_method: "POST",
        submit_path: "/api/v1/exceptions",
    },
];

/// Control-plane routes.
pub fn control_routes() -> Router<AppState> {
    let mut api = Router::new();
    for def in resources::ALL {
        if resources::CUSTOM_CREATE.contains(&def.name) {
            api = api.merge(read_update_routes(def));
        } else {
            api = api.merge(aether_kit::resource::routes::<AppState>(def));
        }
    }
    api.merge(meta_routes_full(PRODUCT, LABEL, resources::ALL, META, DASHBOARDS, WIZARDS))
        .merge(assets::routes())
        .merge(ingest::routes())
        .merge(segmentation::routes())
        .merge(remote::routes())
        .merge(findings::routes())
        .merge(ops::routes())
        .merge(hooks::routes())
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
}

/// Kit routes without the generic create (creation goes through a workflow).
fn read_update_routes(def: &'static aether_kit::resource::ResourceDef) -> Router<AppState> {
    use aether_kit::{resource, ApiResult, Ctx, Envelope};
    use axum::extract::{Path, Query};
    use std::collections::HashMap;
    use uuid::Uuid;
    Router::new()
        .route(&format!("/api/v1/{}", def.name), get(move |ctx: Ctx, Query(q): Query<HashMap<String, String>>| async move { resource::list(&ctx, def, &q).await }))
        .route(
            &format!("/api/v1/{}/{{id}}", def.name),
            get(move |ctx: Ctx, Path(id): Path<Uuid>| async move { resource::get(&ctx, def, id).await })
                .patch(move |ctx: Ctx, Path(id): Path<Uuid>, headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| async move {
                    resource::update(&ctx, def, id, &headers, body).await
                })
                .delete(move |ctx: Ctx, Path(id): Path<Uuid>, headers: axum::http::HeaderMap| async move { resource::delete(&ctx, def, id, &headers).await }),
        )
        .route(
            &format!("/api/v1/{}/{{id}}/dependents", def.name),
            get(move |ctx: Ctx, Path(id): Path<Uuid>| async move {
                ctx.require(def.read)?;
                let mut tx = ctx.tx().await?;
                resource::fetch_visible(&mut tx, &ctx, def, id).await?;
                let d = resource::dependents(&mut tx, def, id).await?;
                tx.commit().await?;
                ApiResult::Ok(Envelope::ok(&ctx, d))
            }),
        )
}

pub fn router(state: AppState) -> Router {
    let metrics = state.metrics.clone();
    control_routes()
        .with_state(state.clone())
        .layer(RequestBodyLimitLayer::new(state.cfg.max_request_body))
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, state.cfg.request_timeout))
        .layer(axum::middleware::from_fn(move |req, next| middleware::observe(metrics.clone(), req, next)))
        .layer(axum::middleware::from_fn(trace_context))
        .layer(axum::middleware::from_fn(middleware::security_headers))
        .layer(CatchPanicLayer::new())
}

/// W3C trace context for every request, made current for dependency calls
/// and echoed in the response.
async fn trace_context(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let trace = crate::telemetry::TraceContext::from_header(req.headers().get("traceparent").and_then(|v| v.to_str().ok()));
    let header = trace.header();
    let span = tracing::info_span!("request", component = "iot-ot", version = env!("CARGO_PKG_VERSION"), trace_id = %trace.trace_id, span_id = %trace.span_id);
    let mut res = tracing::Instrument::instrument(crate::telemetry::TRACE.scope(trace, next.run(req)), span).await;
    if let Ok(v) = axum::http::HeaderValue::from_str(&header) {
        res.headers_mut().insert("traceparent", v);
    }
    res
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (axum::http::StatusCode::OK, Json(json!({"status": "ready", "platform": state.platform.health(), "ingest_permits": state.ingest.available_permits()}))),
        Err(e) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({"status": "not_ready", "database": e.to_string()}))),
    }
}

async fn metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let bind = state.cfg.bind.clone();
    if state.cfg.workers {
        crate::workers::spawn(state.clone());
    }
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "Aether IoT/OT Security listening");
    axum::serve(listener, router(state).into_make_service_with_connect_info::<std::net::SocketAddr>()).with_graceful_shutdown(crate::shutdown_signal()).await?;
    Ok(())
}
