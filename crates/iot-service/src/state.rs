//! Service state shared by the API, the ingestion pipeline and the workers
//! (section 114 Caches: bounded, short-TTL per-tenant caches invalidated on
//! change).

use crate::config::ServeConfig;
use crate::integrations::{Branch, Firewall, Integrations, PrivateAccess};
use crate::platform::Platform;
use crate::telemetry::Telemetry;
use aether_kit::auth::Verifier;
use aether_kit::crypto::Keyring;
use aether_kit::http::ratelimit::RateLimiter;
use aether_kit::metrics::Metrics;
use aether_kit::KitState;
use dashmap::DashMap;
use iot_core::classify::Classifier;
use iot_core::vuln::VulnFeed;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use uuid::Uuid;

pub const SERVICE_NAME: &str = "aether-iot-ot";
/// Product key (platform entitlement, policy types `iot.*`, console path `/svc/iot`).
pub const PRODUCT: &str = "iot";
pub const LABEL: &str = "IoT/OT Security";

pub const READ: &str = "policy.iot:read";
pub const CREATE: &str = "policy.iot:create";
pub const UPDATE: &str = "policy.iot:update";
pub const DELETE: &str = "policy.iot:delete";
pub const ACTIVATE: &str = "policy.iot:activate";

/// Node kinds allowed to act as IoT/OT edge collectors/enforcers.
pub const EDGE_NODE_KINDS: &[&str] = &["branch_connector", "private_edge", "service_edge"];

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

pub struct Inner {
    pub pool: PgPool,
    pub verifier: Verifier,
    pub limiter: RateLimiter,
    pub metrics: Metrics,
    pub telemetry: Telemetry,
    pub platform: Platform,
    pub keyring: Keyring,
    pub cfg: ServeConfig,
    pub peers: Integrations,
    pub feed: std::sync::RwLock<Arc<dyn VulnFeed>>,
    pub feed_loaded_at: std::sync::RwLock<chrono::DateTime<chrono::Utc>>,
    /// Backpressure for observation ingestion.
    pub ingest: Arc<Semaphore>,
    /// Per-tenant classifier (built-in + tenant rules), short TTL.
    pub classifiers: DashMap<Uuid, (Instant, Arc<Classifier>)>,
    /// Per-tenant active `iot.segmentation` policy, short TTL.
    pub policies: DashMap<Uuid, (Instant, Option<Arc<aether_core::policy::eval::PreparedPolicy>>)>,
    pub revocations: DashMap<Uuid, Arc<aether_kit::session::RevocationFeed>>,
    pub started: Instant,
    /// Last time the dependency graph was rebuilt per tenant.
    pub graph_built: DashMap<Uuid, chrono::DateTime<chrono::Utc>>,
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl KitState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
    fn verifier(&self) -> &Verifier {
        &self.verifier
    }
    fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }
    fn rate_limit_per_minute(&self) -> u32 {
        self.cfg.rate_limit_per_minute
    }
    fn service_name(&self) -> &'static str {
        SERVICE_NAME
    }

    /// Reject tokens of revoked admin sessions (platform revocation feed).
    fn admit(&self, p: &aether_kit::auth::Principal, _meta: &aether_kit::auth::RequestMeta) -> impl std::future::Future<Output = aether_kit::ApiResult<()>> + Send {
        let revoked = self.revocations.get(&p.tenant_id).map(|f| p.session_id.map(|s| f.is_revoked(&s)).unwrap_or(false) || f.is_revoked(&p.actor_id)).unwrap_or(false);
        async move {
            if revoked {
                Err(aether_kit::ApiError::unauthorized("session revoked"))
            } else {
                Ok(())
            }
        }
    }

    fn admit_user(&self, u: &aether_kit::auth::UserClaims, _meta: &aether_kit::auth::RequestMeta) -> impl std::future::Future<Output = aether_kit::ApiResult<()>> + Send {
        let revoked = self.revocations.get(&u.tid).map(|f| f.any_revoked([&u.sid, &u.sub].into_iter().chain(u.did.as_ref()))).unwrap_or(false);
        async move {
            if revoked {
                Err(aether_kit::ApiError::unauthorized("session revoked"))
            } else {
                Ok(())
            }
        }
    }
}

const CACHE_TTL: Duration = Duration::from_secs(30);

impl AppState {
    pub fn new(pool: PgPool, cfg: ServeConfig) -> anyhow::Result<AppState> {
        let p = &cfg.platform;
        let verifier = Verifier::remote(&p.issuer, &p.audience, &format!("{}/.well-known/jwks.json", p.url));
        Self::with_verifier(pool, cfg, verifier)
    }

    pub fn with_verifier(pool: PgPool, cfg: ServeConfig, verifier: Verifier) -> anyhow::Result<AppState> {
        let platform = Platform::new(&cfg.platform)?;
        let metrics = Metrics::new("aether_iot");
        let telemetry = Telemetry::new(&metrics, "aether_iot");
        let peers = Integrations::from_config(&cfg.peers, platform.clone())?;
        Ok(AppState(Arc::new(Inner {
            keyring: Keyring::new(cfg.keys.clone()),
            pool,
            verifier,
            limiter: RateLimiter::default(),
            telemetry,
            metrics,
            peers,
            feed: std::sync::RwLock::new(Arc::new(iot_core::vuln::OfflineFeed::sample())),
            feed_loaded_at: std::sync::RwLock::new(chrono::Utc::now()),
            ingest: Arc::new(Semaphore::new(cfg.ingest_concurrency.max(1))),
            classifiers: DashMap::new(),
            policies: DashMap::new(),
            revocations: DashMap::new(),
            started: Instant::now(),
            graph_built: DashMap::new(),
            platform,
            cfg,
        })))
    }

    /// Replace the peer-product integrations (tests, embedding).
    pub fn with_peers(self, branch: Arc<dyn Branch>, pa: Arc<dyn PrivateAccess>, fw: Arc<dyn Firewall>) -> AppState {
        let inner = Arc::try_unwrap(self.0).unwrap_or_else(|_| panic!("with_peers must be called before the state is shared"));
        AppState(Arc::new(Inner { peers: Integrations { branch, private_access: pa, firewall: fw }, ..inner }))
    }

    pub fn feed(&self) -> Arc<dyn VulnFeed> {
        self.feed.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_feed(&self, f: Arc<dyn VulnFeed>) {
        *self.feed.write().unwrap_or_else(|e| e.into_inner()) = f;
        *self.feed_loaded_at.write().unwrap_or_else(|e| e.into_inner()) = chrono::Utc::now();
    }

    pub fn feed_age_secs(&self) -> i64 {
        (chrono::Utc::now() - *self.feed_loaded_at.read().unwrap_or_else(|e| e.into_inner())).num_seconds()
    }

    /// The tenant's classifier (cached).
    pub async fn classifier(&self, tenant: Uuid) -> anyhow::Result<Arc<Classifier>> {
        if let Some(e) = self.classifiers.get(&tenant) {
            if e.0.elapsed() < CACHE_TTL {
                return Ok(e.1.clone());
            }
        }
        let mut tx = aether_kit::db::tenant_tx(&self.pool, tenant).await?;
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT jsonb_build_object('id', id::text, 'source', source, 'field', field, 'match', match, 'pattern', pattern, 'device_type', device_type, 'vendor', vendor, 'model', model, 'os', os, 'weight', weight, 'origin', origin)
             FROM classification_rules WHERE deleted_at IS NULL AND enabled ORDER BY origin, created_at LIMIT 5000",
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let rules: Vec<iot_core::classify::Rule> = rows.into_iter().filter_map(|r| serde_json::from_value(r.0).ok()).collect();
        let c = Arc::new(Classifier::new(rules));
        self.classifiers.insert(tenant, (Instant::now(), c.clone()));
        Ok(c)
    }

    pub fn invalidate(&self, tenant: Uuid) {
        self.classifiers.remove(&tenant);
        self.policies.remove(&tenant);
    }

    /// The tenant's active segmentation policy from the platform (cached;
    /// `None` when none is active or the platform is not configured).
    pub async fn segmentation_policy(&self, tenant: Uuid) -> Option<Arc<aether_core::policy::eval::PreparedPolicy>> {
        if let Some(e) = self.policies.get(&tenant) {
            if e.0.elapsed() < CACHE_TTL {
                return e.1.clone();
            }
        }
        if !self.platform.configured() {
            return None;
        }
        let p = match self.platform.active_policies(tenant, iot_core::policy::SEGMENTATION).await {
            Ok(list) => list.into_iter().find(|c| c.policy_type == iot_core::policy::SEGMENTATION).map(|c| Arc::new(aether_core::policy::eval::PreparedPolicy::new(c))),
            Err(e) => {
                tracing::warn!(error = %e, "segmentation policy unavailable; keeping the cached one");
                return self.policies.get(&tenant).and_then(|e| e.1.clone());
            }
        };
        self.policies.insert(tenant, (Instant::now(), p.clone()));
        p
    }

    pub fn revocation_feed(&self, tenant: Uuid) -> Arc<aether_kit::session::RevocationFeed> {
        self.revocations.entry(tenant).or_default().clone()
    }
}
