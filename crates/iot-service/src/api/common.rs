//! Shared request checks and helpers for custom handlers.

use crate::state::{EDGE_NODE_KINDS, PRODUCT};
use aether_kit::auth::TokenExtras;
use aether_kit::{ActorType, ApiError, ApiResult, Ctx};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Administrator/API-client/service request: entitlement and permission;
/// node tokens are refused (nodes only reach the `/api/v1/node/*` APIs).
pub fn pre(ctx: &Ctx, perm: &str) -> ApiResult<()> {
    if ctx.p.actor_type == ActorType::Node {
        return Err(ApiError::forbidden("enforcement nodes may not call this API"));
    }
    ctx.require_entitlement(PRODUCT)?;
    ctx.require(perm)
}

/// Node request: an enrolled IoT/OT edge node of an allowed kind.
pub fn node(ctx: &Ctx, x: &TokenExtras) -> ApiResult<String> {
    if ctx.p.actor_type != ActorType::Node {
        return Err(ApiError::forbidden("only enrolled edge nodes may call this API"));
    }
    ctx.require_entitlement(PRODUCT)?;
    let kind = x.node_kind.as_deref().unwrap_or("");
    if !kind.is_empty() && !EDGE_NODE_KINDS.contains(&kind) {
        return Err(ApiError::forbidden(format!("node kind {kind} cannot act as an IoT/OT edge")));
    }
    Ok(ctx.p.actor_id.to_string())
}

pub fn q_uuid(q: &HashMap<String, String>, k: &str) -> ApiResult<Option<Uuid>> {
    q.get(k).filter(|v| !v.is_empty()).map(|v| Uuid::parse_str(v).map_err(|_| ApiError::field(k, "invalid_uuid", "must be a UUID"))).transpose()
}

pub fn limit(q: &HashMap<String, String>) -> i64 {
    q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(100).clamp(1, 1000)
}

pub fn body_str<'a>(b: &'a Value, k: &str) -> Option<&'a str> {
    b.get(k).and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Keyset cursor over (text sort key, id).
pub fn cursor(q: &HashMap<String, String>) -> ApiResult<Option<(String, Uuid)>> {
    match q.get("cursor").filter(|c| !c.is_empty()) {
        None => Ok(None),
        Some(c) => {
            let p = aether_kit::http::pagination::decode(c).map_err(|_| ApiError::field("cursor", "invalid_cursor", "malformed cursor"))?;
            let id = Uuid::parse_str(&p.id).map_err(|_| ApiError::field("cursor", "invalid_cursor", "malformed cursor"))?;
            Ok(Some((p.k, id)))
        }
    }
}

pub fn next_cursor(k: String, id: Uuid) -> String {
    aether_kit::http::pagination::encode(&aether_kit::http::pagination::Cursor { k, id: id.to_string() })
}
