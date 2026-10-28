//! Peer product integrations over their documented HTTP APIs, behind
//! traits with fallbacks (ZTE-IOT sections 57, 79 private application
//! access, 80 Zero Trust Branch Integration, 81 Branch Enforcement, 87–91
//! remote access; docs/integration.md §11).
//!
//! * [`Branch`] — pulls the device observations branch edges report
//!   (`GET /api/v1/inventory` of Aether Branch) as integration assertions,
//!   so devices behind branch appliances join the inventory.
//! * [`PrivateAccess`] — privileged remote access is brokered by Aether
//!   Private Access: a just-in-time window becomes a privileged approval
//!   (`POST /api/v1/privileged-approvals`) for the console's application
//!   segment; sessions and recording metadata are read back
//!   (`/api/v1/privileged-sessions`, `/api/v1/privileged-recordings`) and
//!   sessions can be terminated.
//! * [`Firewall`] — device identities are published as identity bindings
//!   (`POST /api/v1/identity-bindings/upsert`) so cloud firewall rules
//!   using the `iot.*` extension operands resolve devices by address.
//!
//! Every call carries a tenant-scoped service token, runs with timeouts,
//! retries and the platform client's circuit breaker; when a peer is not
//! configured or refuses, the fallback keeps the product working (local
//! JIT windows and session records, no branch enrichment, no firewall
//! bindings) and the condition is reported in `/api/v1/integrations`.

use crate::config::PeerConfig;
use crate::platform::{PResult, Platform, PlatformError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

/// A device observation reported by a branch edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BranchDevice {
    pub mac: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub last_seen: Option<DateTime<Utc>>,
}

/// Map a branch device class onto this product's taxonomy.
pub fn branch_class(c: &str) -> Option<&'static str> {
    Some(match c {
        "workstation" => "workstation",
        "mobile" => "mobile",
        "printer" => "printer",
        "camera" => "ip_camera",
        "voip_phone" => "voip_phone",
        "media" => "media_player",
        "iot_sensor" => "iot_sensor",
        "ot_controller" => "plc",
        "network" => "switch",
        "server" => "server",
        _ => return None,
    })
}

#[async_trait]
pub trait Branch: Send + Sync {
    fn name(&self) -> &'static str;
    fn configured(&self) -> bool;
    /// One page of device observations after `cursor`.
    async fn devices(&self, tenant: Uuid, cursor: Option<String>) -> PResult<(Vec<BranchDevice>, Option<String>)>;
}

/// Grant for a just-in-time window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    /// `private_access` or `local`.
    pub source: String,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokerSession {
    pub id: String,
    pub user: String,
    pub state: String,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub recording: Option<Value>,
}

#[async_trait]
pub trait PrivateAccess: Send + Sync {
    fn name(&self) -> &'static str;
    fn configured(&self) -> bool;
    async fn grant(&self, tenant: Uuid, email: &str, console_id: &str, start: DateTime<Utc>, end: DateTime<Utc>, reason: &str) -> PResult<Grant>;
    async fn revoke(&self, tenant: Uuid, grant: &Grant) -> PResult<()>;
    /// Sessions of a console (and their recording metadata).
    async fn sessions(&self, tenant: Uuid, console_id: &str) -> PResult<Vec<BrokerSession>>;
    async fn terminate(&self, tenant: Uuid, session_id: &str) -> PResult<()>;
}

#[async_trait]
pub trait Firewall: Send + Sync {
    fn name(&self) -> &'static str;
    fn configured(&self) -> bool;
    /// Publish (address, device id) bindings.
    async fn bind(&self, tenant: Uuid, bindings: &[(String, Uuid)]) -> PResult<usize>;
}

/// The configured integrations.
#[derive(Clone)]
pub struct Integrations {
    pub branch: Arc<dyn Branch>,
    pub private_access: Arc<dyn PrivateAccess>,
    pub firewall: Arc<dyn Firewall>,
}

impl Integrations {
    pub fn from_config(c: &PeerConfig, platform: Platform) -> anyhow::Result<Integrations> {
        Ok(Integrations {
            branch: match &c.branch_url {
                Some(u) => Arc::new(HttpBranch { base: u.trim_end_matches('/').into(), platform: platform.clone() }),
                None => Arc::new(NoBranch),
            },
            private_access: match &c.private_access_url {
                Some(u) => Arc::new(HttpPrivateAccess { base: u.trim_end_matches('/').into(), platform: platform.clone() }),
                None => Arc::new(LocalAccess),
            },
            firewall: match &c.firewall_url {
                Some(u) => Arc::new(HttpFirewall { base: u.trim_end_matches('/').into(), platform }),
                None => Arc::new(NoFirewall),
            },
        })
    }

    pub fn status(&self) -> Value {
        json!({
            "branch": { "integration": self.branch.name(), "configured": self.branch.configured() },
            "private_access": { "integration": self.private_access.name(), "configured": self.private_access.configured() },
            "firewall": { "integration": self.firewall.name(), "configured": self.firewall.configured() },
        })
    }
}

async fn peer_call(platform: &Platform, tenant: Uuid, method: Method, url: &str, body: Option<&Value>, headers: &[(&str, String)]) -> PResult<Value> {
    let token = platform.service_token(Some(tenant)).await?;
    let idempotent = matches!(method, Method::GET | Method::PUT | Method::DELETE);
    let res = platform.send(method, url, Some(&token), body, headers, idempotent).await?;
    let status = res.status().as_u16();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(PlatformError::Status { status, code: v["code"].as_str().unwrap_or("error").into(), detail: v["detail"].as_str().unwrap_or("").into() });
    }
    Ok(v)
}

pub struct HttpBranch {
    base: String,
    platform: Platform,
}

#[async_trait]
impl Branch for HttpBranch {
    fn name(&self) -> &'static str {
        "aether-branch"
    }
    fn configured(&self) -> bool {
        true
    }
    async fn devices(&self, tenant: Uuid, cursor: Option<String>) -> PResult<(Vec<BranchDevice>, Option<String>)> {
        let mut url = format!("{}/api/v1/inventory?limit=500", self.base);
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", percent_encoding::utf8_percent_encode(&c, percent_encoding::NON_ALPHANUMERIC)));
        }
        let v = peer_call(&self.platform, tenant, Method::GET, &url, None, &[]).await?;
        let items: Vec<BranchDevice> = v["data"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|d| serde_json::from_value(d).ok()).collect();
        Ok((items, v["meta"]["next_cursor"].as_str().map(String::from)))
    }
}

pub struct NoBranch;

#[async_trait]
impl Branch for NoBranch {
    fn name(&self) -> &'static str {
        "none"
    }
    fn configured(&self) -> bool {
        false
    }
    async fn devices(&self, _: Uuid, _: Option<String>) -> PResult<(Vec<BranchDevice>, Option<String>)> {
        Ok((vec![], None))
    }
}

pub struct HttpPrivateAccess {
    base: String,
    platform: Platform,
}

#[async_trait]
impl PrivateAccess for HttpPrivateAccess {
    fn name(&self) -> &'static str {
        "aether-private-access"
    }
    fn configured(&self) -> bool {
        true
    }
    async fn grant(&self, tenant: Uuid, email: &str, console_id: &str, start: DateTime<Utc>, end: DateTime<Utc>, reason: &str) -> PResult<Grant> {
        let console = peer_call(&self.platform, tenant, Method::GET, &format!("{}/api/v1/privileged-consoles/{console_id}", self.base), None, &[]).await?;
        let segment = console["data"]["segment_id"].as_str().ok_or_else(|| PlatformError::Decode("console without segment".into()))?.to_string();
        let body = json!({ "email": email, "application_ids": [segment], "start_time": start, "end_time": end, "reason": reason, "source": "access_request" });
        let v =
            peer_call(&self.platform, tenant, Method::POST, &format!("{}/api/v1/privileged-approvals", self.base), Some(&body), &[("idempotency-key", Uuid::now_v7().to_string())])
                .await?;
        let id = v["data"]["id"].as_str().ok_or_else(|| PlatformError::Decode("no approval id".into()))?;
        Ok(Grant { source: "private_access".into(), reference: id.into() })
    }
    async fn revoke(&self, tenant: Uuid, grant: &Grant) -> PResult<()> {
        if grant.source != "private_access" {
            return Ok(());
        }
        let url = format!("{}/api/v1/privileged-approvals/{}", self.base, grant.reference);
        let cur = peer_call(&self.platform, tenant, Method::GET, &url, None, &[]).await?;
        let ver = cur["data"]["version"].as_i64().unwrap_or(1);
        peer_call(&self.platform, tenant, Method::PATCH, &url, Some(&json!({ "revoked": true })), &[("if-match", format!("\"v{ver}\""))]).await?;
        Ok(())
    }
    async fn sessions(&self, tenant: Uuid, console_id: &str) -> PResult<Vec<BrokerSession>> {
        let v = peer_call(&self.platform, tenant, Method::GET, &format!("{}/api/v1/privileged-sessions", self.base), None, &[]).await?;
        let recs = peer_call(&self.platform, tenant, Method::GET, &format!("{}/api/v1/privileged-recordings", self.base), None, &[]).await.unwrap_or(Value::Null);
        let recs = recs["data"].as_array().cloned().unwrap_or_default();
        Ok(v["data"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s["console_id"].as_str() == Some(console_id))
            .map(|s| {
                let id = s["id"].as_str().unwrap_or_default().to_string();
                BrokerSession {
                    recording: recs.iter().find(|r| r["session_id"].as_str() == Some(&id)).map(|r| json!({ "recording_id": r["id"], "sha256": r["sha256"], "size_bytes": r["size_bytes"], "duration_ms": r["duration_ms"], "stored_by": "private_access" })),
                    user: s["user_name"].as_str().or(s["user_email"].as_str()).unwrap_or_default().to_string(),
                    state: s["state"].as_str().unwrap_or_default().to_string(),
                    started_at: s["started_at"].as_str().and_then(|t| t.parse().ok()),
                    ended_at: s["ended_at"].as_str().and_then(|t| t.parse().ok()),
                    id,
                }
            })
            .collect())
    }
    async fn terminate(&self, tenant: Uuid, session_id: &str) -> PResult<()> {
        peer_call(&self.platform, tenant, Method::POST, &format!("{}/api/v1/privileged-sessions/{session_id}/terminate", self.base), Some(&json!({})), &[]).await.map(|_| ())
    }
}

/// Fallback: JIT windows enforced and recorded by this product only.
pub struct LocalAccess;

impl LocalAccess {
    /// A grant recorded by this product only (no broker).
    pub fn grant_local(&self) -> Grant {
        Grant { source: "local".into(), reference: Uuid::now_v7().to_string() }
    }
}

#[async_trait]
impl PrivateAccess for LocalAccess {
    fn name(&self) -> &'static str {
        "local"
    }
    fn configured(&self) -> bool {
        false
    }
    async fn grant(&self, _: Uuid, _: &str, _: &str, _: DateTime<Utc>, _: DateTime<Utc>, _: &str) -> PResult<Grant> {
        Ok(Grant { source: "local".into(), reference: Uuid::now_v7().to_string() })
    }
    async fn revoke(&self, _: Uuid, _: &Grant) -> PResult<()> {
        Ok(())
    }
    async fn sessions(&self, _: Uuid, _: &str) -> PResult<Vec<BrokerSession>> {
        Ok(vec![])
    }
    async fn terminate(&self, _: Uuid, _: &str) -> PResult<()> {
        Ok(())
    }
}

pub struct HttpFirewall {
    base: String,
    platform: Platform,
}

#[async_trait]
impl Firewall for HttpFirewall {
    fn name(&self) -> &'static str {
        "aether-firewall"
    }
    fn configured(&self) -> bool {
        true
    }
    async fn bind(&self, tenant: Uuid, bindings: &[(String, Uuid)]) -> PResult<usize> {
        let mut n = 0;
        for chunk in bindings.chunks(1000) {
            let body: Vec<Value> = chunk.iter().map(|(ip, id)| json!({ "address": ip, "device_id": id, "ttl_secs": 86_400, "source": "integration" })).collect();
            peer_call(&self.platform, tenant, Method::POST, &format!("{}/api/v1/identity-bindings/upsert", self.base), Some(&Value::Array(body)), &[]).await?;
            n += chunk.len();
        }
        Ok(n)
    }
}

pub struct NoFirewall;

#[async_trait]
impl Firewall for NoFirewall {
    fn name(&self) -> &'static str {
        "none"
    }
    fn configured(&self) -> bool {
        false
    }
    async fn bind(&self, _: Uuid, _: &[(String, Uuid)]) -> PResult<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_classes_map_to_taxonomy() {
        for c in ["workstation", "mobile", "printer", "camera", "voip_phone", "media", "iot_sensor", "ot_controller", "network", "server"] {
            assert!(iot_core::taxonomy::is_known(branch_class(c).unwrap()), "{c}");
        }
        assert_eq!(branch_class("toaster"), None);
    }

    #[tokio::test]
    async fn fallbacks_keep_working() {
        let g = LocalAccess.grant(Uuid::nil(), "v@example.com", "c", Utc::now(), Utc::now(), "r").await.unwrap();
        assert_eq!(g.source, "local");
        assert!(NoBranch.devices(Uuid::nil(), None).await.unwrap().0.is_empty());
        assert_eq!(NoFirewall.bind(Uuid::nil(), &[("10.0.0.1".into(), Uuid::nil())]).await.unwrap(), 0);
    }
}
