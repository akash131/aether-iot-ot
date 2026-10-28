//! Aether IoT/OT Security service.
//!
//! * [`api`] — the product control plane: sites, sensors, zones, device
//!   groups, asset inventory, classification, risk, findings, anomalies,
//!   segmentation, privileged remote access, node APIs for edges;
//! * [`pipeline`] — observation ingestion, classification, risk scoring,
//!   baselines and anomaly detection;
//! * [`workers`] — log/signal shipping, approval sync, remote-access
//!   supervision, integrations, retention;
//! * [`edge`] — the edge appliance (collector/enforcer node);
//! * [`platform`] / [`integrations`] — the platform client and the peer
//!   product integrations (behind traits with fallbacks).

// `ApiError` is the shared problem+json type of every Aether service.
#![allow(clippy::result_large_err)]
// SQL rows are decoded into tuples.
#![allow(clippy::type_complexity)]

pub mod api;
pub mod config;
pub mod edge;
pub mod integrations;
pub mod pipeline;
pub mod platform;
pub mod state;
pub mod telemetry;
pub mod workers;

use anyhow::Result;

/// Apply the kit base schema and this product's migrations.
pub async fn migrate(pool: &sqlx::PgPool) -> Result<()> {
    aether_kit::db::apply_base_schema(pool).await?;
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}
