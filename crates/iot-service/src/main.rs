//! `aether-iot` — Aether IoT/OT Security.
//!
//! ```text
//! aether-iot serve                  control plane and workers
//! aether-iot edge                   edge appliance (collector / enforcer node)
//! aether-iot migrate                apply database migrations and exit
//! aether-iot register-policy-types  register iot.* policy types, log schemas and hooks
//! aether-iot analyze <file.pcap>    offline passive analysis of a capture file
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use iot_service::config::{EdgeConfig, ServeConfig};
use iot_service::state::AppState;

#[derive(Parser)]
#[command(name = "aether-iot", version, about = "Aether IoT/OT Security: device discovery, classification, risk, OT protocol awareness, segmentation and privileged remote access")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the control-plane API (and run workers unless IOT_WORKERS=false).
    Serve,
    /// Run the edge appliance node.
    Edge,
    /// Apply database migrations and exit.
    Migrate,
    /// Register policy types, the firewall extension, log schemas and hooks, then exit.
    RegisterPolicyTypes,
    /// Analyse a capture file offline and print the observations (JSON).
    Analyze { file: String },
}

async fn register(platform: &iot_service::platform::Platform) -> Result<()> {
    let n = platform.register_policy_types().await.map_err(|e| anyhow::anyhow!("policy types: {e}"))?;
    tracing::info!(types = n, "policy types registered with the platform");
    match platform.register_log_schemas().await {
        Ok(n) => tracing::info!(schemas = n, "log schemas registered"),
        Err(e) => tracing::warn!(error = %e, "log schema registration failed"),
    }
    match platform.register_service_hooks().await {
        Ok(_) => tracing::info!("policy reference and simulation hooks declared"),
        Err(e) => tracing::warn!(error = %e, "service hook declaration failed (register the service with --base-url)"),
    }
    Ok(())
}

async fn serve() -> Result<()> {
    let cfg = ServeConfig::from_env()?;
    let pool = aether_kit::db::connect(&cfg.database_url, cfg.db_max_connections, "aether-iot").await?;
    if cfg.run_migrations {
        iot_service::migrate(&pool).await?;
    }
    aether_kit::db::assert_rls_effective(&pool, cfg.production).await?;
    let state = AppState::new(pool, cfg)?;
    if state.platform.has_service_credentials() {
        let s = state.clone();
        tokio::spawn(async move {
            for attempt in 0..10u32 {
                match register(&s.platform).await {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(error = %e, attempt, "platform registration failed; retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(5 * (attempt as u64 + 1))).await;
                    }
                }
            }
        });
    }
    iot_service::api::serve(state).await
}

async fn edge() -> Result<()> {
    let cfg = EdgeConfig::from_env()?;
    let bind = cfg.admin_bind.clone();
    let agent = iot_service::edge::Agent::start(cfg).await?;
    agent.spawn_loops();
    tokio::select! {
        r = iot_service::edge::admin::serve_admin(agent.clone(), bind) => r,
        _ = iot_service::shutdown_signal() => {
            if let Err(e) = agent.flush().await {
                tracing::warn!(error = %e, "final flush failed");
            }
            tracing::info!("edge shutting down");
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    aether_kit::telemetry::init_tracing(std::env::var("IOT_LOG_JSON").is_ok(), "IOT_LOG");
    match cli.cmd {
        Cmd::Serve => serve().await,
        Cmd::Edge => edge().await,
        Cmd::Migrate => {
            let cfg = ServeConfig::from_env()?;
            let pool = aether_kit::db::connect(&cfg.database_url, 2, "aether-iot-migrate").await?;
            iot_service::migrate(&pool).await?;
            tracing::info!("database migrations applied");
            Ok(())
        }
        Cmd::RegisterPolicyTypes => {
            let cfg = ServeConfig::from_env()?;
            let platform = iot_service::platform::Platform::new(&cfg.platform)?;
            register(&platform).await
        }
        Cmd::Analyze { file } => {
            let mut c = iot_core::collect::Collector::default();
            let f = std::fs::File::open(&file)?;
            let mut r = iot_core::packet::PcapReader::new(std::io::BufReader::new(f)).map_err(|e| anyhow::anyhow!("{}", e.code()))?;
            while let Ok(Some(rec)) = r.next_record() {
                c.ingest(rec.ts_micros, &rec.data);
            }
            let obs = c.drain(None, None);
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "stats": c.stats, "observations": obs }))?);
            Ok(())
        }
    }
}
