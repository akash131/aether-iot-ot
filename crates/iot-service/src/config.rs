//! Runtime configuration from environment variables (12-factor). Secrets
//! (service credentials, encryption keys, provisioning keys) are never
//! printed (section 115 Secrets And PKI; section 119 Sovereignty: the data
//! region a deployment serves is pinned with `IOT_DATA_REGION`).

use anyhow::{bail, Context, Result};
use base64::Engine;
use std::time::Duration;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn parse_or<T: std::str::FromStr>(name: &str, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match var(name) {
        Some(v) => v.trim().parse::<T>().map_err(|e| anyhow::anyhow!("{name}: {e}")),
        None => Ok(default),
    }
}

/// Platform connection.
#[derive(Clone)]
pub struct PlatformConfig {
    pub url: String,
    pub issuer: String,
    pub audience: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl std::fmt::Debug for PlatformConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformConfig").field("url", &self.url).field("issuer", &self.issuer).field("client_id", &self.client_id).finish_non_exhaustive()
    }
}

impl PlatformConfig {
    pub fn from_env() -> Self {
        let url = var("AETHER_PLATFORM_URL").unwrap_or_else(|| "http://localhost:8080".into()).trim_end_matches('/').to_string();
        PlatformConfig {
            issuer: var("AETHER_ISSUER").unwrap_or_else(|| url.clone()),
            audience: var("AETHER_AUDIENCE").unwrap_or_else(|| "aether".into()),
            client_id: var("IOT_CLIENT_ID"),
            client_secret: var("IOT_CLIENT_SECRET"),
            url,
        }
    }
}

/// Peer product endpoints (integrations behind traits with fallbacks).
#[derive(Clone, Debug, Default)]
pub struct PeerConfig {
    /// Aether Branch control plane (device observations of branch edges).
    pub branch_url: Option<String>,
    /// Aether Private Access control plane (privileged consoles, approvals, sessions).
    pub private_access_url: Option<String>,
    /// Aether Firewall control plane (identity bindings).
    pub firewall_url: Option<String>,
    /// Vulnerability feed document URL (JSON in the feed format); the
    /// bundled sample feed is used when unset.
    pub vuln_feed_url: Option<String>,
}

impl PeerConfig {
    pub fn from_env() -> Self {
        PeerConfig {
            branch_url: var("IOT_BRANCH_URL"),
            private_access_url: var("IOT_PRIVATE_ACCESS_URL"),
            firewall_url: var("IOT_FIREWALL_URL"),
            vuln_feed_url: var("IOT_VULN_FEED_URL"),
        }
    }
}

#[derive(Clone)]
pub struct ServeConfig {
    pub bind: String,
    pub database_url: String,
    pub db_max_connections: u32,
    pub production: bool,
    pub rate_limit_per_minute: u32,
    pub run_migrations: bool,
    pub public_url: String,
    pub platform: PlatformConfig,
    pub peers: PeerConfig,
    /// Keyring for secrets at rest: `(version, key)`, last is current.
    pub keys: Vec<(u8, [u8; 32])>,
    pub workers: bool,
    pub worker_interval_ms: u64,
    /// Concurrent ingestion batches processed (backpressure, 429 beyond).
    pub ingest_concurrency: usize,
    pub max_request_body: usize,
    /// Data region served by this deployment (sovereignty).
    pub data_region: Option<String>,
    /// Retention of raw observations and change history (days).
    pub observation_retention_days: i64,
    pub history_retention_days: i64,
    /// Request timeout for control-plane APIs.
    pub request_timeout: Duration,
}

impl std::fmt::Debug for ServeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeConfig")
            .field("bind", &self.bind)
            .field("production", &self.production)
            .field("platform", &self.platform)
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}

/// Parse `IOT_ENCRYPTION_KEYS` = `1:<base64 32 bytes>,2:<base64>`.
pub fn parse_keys(s: &str) -> Result<Vec<(u8, [u8; 32])>> {
    let mut out = vec![];
    for item in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let (v, k) = item.split_once(':').context("IOT_ENCRYPTION_KEYS entries must be <version>:<base64 key>")?;
        let ver: u8 = v.trim().parse().context("key version must be 0..255")?;
        let raw = base64::engine::general_purpose::STANDARD.decode(k.trim()).context("key must be base64")?;
        let key: [u8; 32] = raw.try_into().map_err(|_| anyhow::anyhow!("key {ver} must be 32 bytes"))?;
        out.push((ver, key));
    }
    if out.is_empty() {
        bail!("no encryption keys");
    }
    Ok(out)
}

impl ServeConfig {
    pub fn from_env() -> Result<Self> {
        let production = matches!(var("IOT_ENV").as_deref(), Some("production" | "prod"));
        let database_url = match var("IOT_DATABASE_URL") {
            Some(u) => u,
            None if production => bail!("IOT_DATABASE_URL is required in production"),
            None => "postgres://aether_iot:aether_iot@localhost:5432/aether_iot".into(),
        };
        let keys = match var("IOT_ENCRYPTION_KEYS") {
            Some(k) => parse_keys(&k)?,
            None if production => bail!("IOT_ENCRYPTION_KEYS is required in production"),
            None => {
                tracing::warn!("IOT_ENCRYPTION_KEYS not set: using a development key (never in production)");
                vec![(1, *b"aether-iot-development-key-00001")]
            }
        };
        Ok(ServeConfig {
            bind: var("IOT_BIND").unwrap_or_else(|| "0.0.0.0:8096".into()),
            database_url,
            db_max_connections: parse_or("IOT_DB_MAX_CONNECTIONS", 20)?,
            production,
            rate_limit_per_minute: parse_or("IOT_RATE_LIMIT_PER_MINUTE", 3000)?,
            run_migrations: parse_or("IOT_RUN_MIGRATIONS", true)?,
            public_url: var("IOT_PUBLIC_URL").unwrap_or_else(|| "http://localhost:8096".into()).trim_end_matches('/').to_string(),
            platform: PlatformConfig::from_env(),
            peers: PeerConfig::from_env(),
            keys,
            workers: parse_or("IOT_WORKERS", true)?,
            worker_interval_ms: parse_or("IOT_WORKER_INTERVAL_MS", 5000)?,
            ingest_concurrency: parse_or("IOT_INGEST_CONCURRENCY", 16)?,
            max_request_body: parse_or("IOT_MAX_REQUEST_BODY", 16 * 1024 * 1024)?,
            data_region: var("IOT_DATA_REGION"),
            observation_retention_days: parse_or("IOT_OBSERVATION_RETENTION_DAYS", 14)?,
            history_retention_days: parse_or("IOT_HISTORY_RETENTION_DAYS", 400)?,
            request_timeout: Duration::from_secs(parse_or("IOT_REQUEST_TIMEOUT_SECS", 60)?),
        })
    }

    /// Configuration for tests and embedded use.
    pub fn for_tests(database_url: &str, platform: PlatformConfig) -> Self {
        ServeConfig {
            bind: "127.0.0.1:0".into(),
            database_url: database_url.into(),
            db_max_connections: 10,
            production: false,
            rate_limit_per_minute: 1_000_000,
            run_migrations: false,
            public_url: "http://127.0.0.1".into(),
            platform,
            peers: PeerConfig::default(),
            keys: vec![(1, [9u8; 32])],
            workers: false,
            worker_interval_ms: 200,
            ingest_concurrency: 8,
            max_request_body: 16 * 1024 * 1024,
            data_region: None,
            observation_retention_days: 14,
            history_retention_days: 400,
            request_timeout: Duration::from_secs(60),
        }
    }
}

/// Edge appliance (collector/enforcer node) configuration.
#[derive(Clone)]
pub struct EdgeConfig {
    pub name: String,
    pub platform: PlatformConfig,
    /// This product's control plane base URL, reached through the platform
    /// gateway (`<platform>/svc/iot`) or directly.
    pub control_url: String,
    pub provisioning_key: Option<String>,
    pub state_dir: String,
    /// Directory polled for capture files (`*.pcap`), processed then removed.
    pub spool_dir: Option<String>,
    /// UDP address receiving TZSP-encapsulated mirrored frames.
    pub tzsp_bind: Option<String>,
    /// Local decision / status API (enforcement points, operators).
    pub admin_bind: String,
    pub heartbeat_interval: Duration,
    pub poll_interval: Duration,
    pub flush_interval: Duration,
    /// Bounded queue of observation batches kept while the control plane
    /// is unreachable.
    pub queue_batches: usize,
    pub config_stale_after: Duration,
    /// Write rendered nftables rules here (host enforcement).
    pub nft_path: Option<String>,
    /// Apply enforcement (otherwise observe-only collector).
    pub enforce: bool,
    /// Bearer token protecting the local admin and decision API.
    pub admin_token: Option<String>,
    /// Allow active queries to be executed by this edge.
    pub active_queries: bool,
}

impl std::fmt::Debug for EdgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeConfig").field("name", &self.name).field("control_url", &self.control_url).field("state_dir", &self.state_dir).finish_non_exhaustive()
    }
}

impl EdgeConfig {
    /// Configuration for tests: offline, everything local.
    pub fn for_tests(state_dir: &str, platform: PlatformConfig) -> Self {
        EdgeConfig {
            name: "test-edge".into(),
            control_url: format!("{}/svc/iot", platform.url),
            provisioning_key: None,
            state_dir: state_dir.into(),
            spool_dir: None,
            tzsp_bind: None,
            admin_bind: "127.0.0.1:0".into(),
            heartbeat_interval: Duration::from_secs(30),
            poll_interval: Duration::from_secs(30),
            flush_interval: Duration::from_secs(10),
            queue_batches: 4,
            config_stale_after: Duration::from_secs(900),
            nft_path: None,
            enforce: false,
            admin_token: Some("test-admin-token".into()),
            active_queries: true,
            platform,
        }
    }

    pub fn from_env() -> Result<Self> {
        let platform = PlatformConfig::from_env();
        let control = var("IOT_CONTROL_URL").unwrap_or_else(|| format!("{}/svc/iot", platform.url));
        Ok(EdgeConfig {
            name: var("IOT_EDGE_NAME").unwrap_or_else(|| "iot-edge".into()),
            control_url: control.trim_end_matches('/').to_string(),
            provisioning_key: var("IOT_PROVISIONING_KEY"),
            state_dir: var("IOT_STATE_DIR").unwrap_or_else(|| "/var/lib/aether-iot".into()),
            spool_dir: var("IOT_SPOOL_DIR"),
            tzsp_bind: var("IOT_TZSP_BIND"),
            admin_bind: var("IOT_EDGE_ADMIN_BIND").unwrap_or_else(|| "127.0.0.1:8097".into()),
            heartbeat_interval: Duration::from_secs(parse_or("IOT_HEARTBEAT_SECS", 30)?),
            poll_interval: Duration::from_secs(parse_or("IOT_POLL_SECS", 30)?),
            flush_interval: Duration::from_secs(parse_or("IOT_FLUSH_SECS", 10)?),
            queue_batches: parse_or("IOT_EDGE_QUEUE_BATCHES", 1000)?,
            config_stale_after: Duration::from_secs(parse_or("IOT_CONFIG_STALE_SECS", 900)?),
            nft_path: var("IOT_NFT_PATH"),
            enforce: parse_or("IOT_EDGE_ENFORCE", false)?,
            admin_token: var("IOT_EDGE_ADMIN_TOKEN"),
            active_queries: parse_or("IOT_EDGE_ACTIVE_QUERIES", true)?,
            platform,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let k = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        assert_eq!(parse_keys(&format!("1:{k},2:{k}")).unwrap().len(), 2);
        assert!(parse_keys("1:abc").is_err());
        assert!(parse_keys("").is_err());
    }
}
