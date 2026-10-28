//! Platform policy hooks (docs/integration.md §8a service hooks; ZTE-IOT
//! sections 83 Policy Simulation, 103 Policy UI, 108 Policy APIs).
//!
//! * `POST /api/v1/policy-hooks/references {policy_type, ref_type, ids}` →
//!   `{missing}`: the platform validates `iot.*` object references (device
//!   groups, zones, sites, vendor principals, devices) in policies.
//! * `POST /api/v1/policy-hooks/simulate {policy_type, context}` →
//!   `{context}`: a platform-side simulation of `iot.segmentation` given
//!   only addresses (or device ids) is enriched with the devices' groups,
//!   zones, types, categories, risk and confidence.

use crate::state::{AppState, READ};
use aether_core::policy::Context;
use aether_kit::{ActorType, ApiError, ApiResult, Ctx, Envelope};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/policy-hooks/references", post(references)).route("/api/v1/policy-hooks/simulate", post(simulate))
}

fn caller(ctx: &Ctx) -> ApiResult<()> {
    if ctx.p.actor_type == ActorType::Service || ctx.has(READ) {
        Ok(())
    } else {
        Err(ApiError::forbidden("platform service token required"))
    }
}

async fn references(ctx: Ctx, Json(b): Json<Value>) -> ApiResult<Envelope> {
    caller(&ctx)?;
    let rt = b["ref_type"].as_str().unwrap_or_default();
    let table = iot_core::policy::REF_TYPES.iter().find(|(k, _)| *k == rt).map(|r| r.1).ok_or_else(|| ApiError::field("ref_type", "unknown_ref_type", rt.to_string()))?;
    let ids: Vec<String> = b["ids"].as_array().cloned().unwrap_or_default().iter().filter_map(|v| v.as_str().map(String::from)).take(1000).collect();
    let uuids: Vec<Uuid> = ids.iter().filter_map(|i| Uuid::parse_str(i).ok()).collect();
    let mut tx = ctx.tx().await?;
    let extra = if table == "assets" { " AND merged_into IS NULL AND lifecycle <> 'decommissioned'" } else { "" };
    let found: Vec<(Uuid,)> = sqlx::query_as(&format!("SELECT id FROM {table} WHERE id = ANY($1) AND deleted_at IS NULL{extra}")).bind(&uuids).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let missing: Vec<&String> = ids.iter().filter(|i| Uuid::parse_str(i).map(|u| !found.iter().any(|f| f.0 == u)).unwrap_or(true)).collect();
    Ok(Envelope::ok(&ctx, json!({ "missing": missing })))
}

async fn simulate(ctx: Ctx, Json(b): Json<Value>) -> ApiResult<Envelope> {
    caller(&ctx)?;
    let c: Context = serde_json::from_value(b["context"].clone()).unwrap_or_default();
    let first = |k: &str| c.attrs.get(k).and_then(|a| a.values.first()).and_then(|v| v.as_str()).map(String::from);
    let mut tx = ctx.tx().await?;
    let mut flow = iot_core::policy::FlowCtx::default();
    let mut resolved: Vec<&str> = vec![];
    for side in ["source", "destination"] {
        let id = match first(&format!("{side}.device")).and_then(|s| Uuid::parse_str(&s).ok()) {
            Some(id) => Some(id),
            None => match first(&format!("{side}.ip")) {
                Some(ip) => sqlx::query_as::<_, (Uuid,)>("SELECT id FROM assets WHERE ip = $1 AND merged_into IS NULL AND deleted_at IS NULL ORDER BY last_seen DESC LIMIT 1")
                    .bind(ip)
                    .fetch_optional(&mut *tx)
                    .await?
                    .map(|r| r.0),
                None => None,
            },
        };
        if let Some(id) = id {
            let d = super::segmentation::device_ctx(&mut tx, id).await?;
            resolved.push(side);
            if side == "source" {
                flow.source = d;
            } else {
                flow.destination = d;
            }
        }
    }
    tx.commit().await?;
    let mut extra = iot_core::policy::segmentation_context(&flow);
    // Only device facts are added; flow attributes stay as the caller set them.
    extra.attrs.retain(|k, _| resolved.iter().any(|s| k.starts_with(&format!("{s}."))) && !k.ends_with(".port"));
    Ok(Envelope::ok(&ctx, json!({ "context": extra })))
}
