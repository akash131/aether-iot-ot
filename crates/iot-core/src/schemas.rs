//! Canonical IoT/OT schemas (ZTE-IOTDATA-153133..153160; ZTE-IOT section
//! 110 Data Schemas): every canonical entity, the table that stores it,
//! its identifier, ownership, lifecycle, provenance/confidence fields,
//! retention class and protection. Served by `GET /api/v1/schemas`.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Entity {
    pub entity: &'static str,
    pub requirement: &'static str,
    /// Table(s) or platform object holding it.
    pub storage: &'static str,
    pub id: &'static str,
    pub ownership: &'static str,
    pub lifecycle: &'static str,
    pub provenance: &'static str,
    pub retention: &'static str,
    pub protection: &'static str,
}

macro_rules! e {
    ($n:expr, $r:expr, $s:expr, $id:expr, $o:expr, $l:expr, $p:expr, $ret:expr, $pr:expr) => {
        Entity { entity: $n, requirement: $r, storage: $s, id: $id, ownership: $o, lifecycle: $l, provenance: $p, retention: $ret, protection: $pr }
    };
}

const T: &str = "tenant_id (RLS)";
const TS: &str = "tenant_id + site_id (RLS)";

pub const ENTITIES: &[Entity] = &[
    e!(
        "DeviceAsset",
        "ZTE-IOTDATA-153133",
        "assets",
        "uuid v7",
        TS,
        "discovered/active/inactive/merged/decommissioned",
        "classification.evidence, identity_strength, confidence",
        "life of asset; history 400 d",
        "RLS; no payloads; audit on change"
    ),
    e!(
        "DeviceIdentity",
        "ZTE-IOTDATA-153134",
        "asset_identities",
        "(asset_id, key_type, value)",
        TS,
        "first_seen/last_seen",
        "key_type (mac/serial/hostname/client_id/ip/tls)",
        "life of asset",
        "RLS; client ids hashed"
    ),
    e!(
        "DeviceObservation",
        "ZTE-IOTDATA-153135",
        "observations",
        "uuid v7",
        TS,
        "append-only",
        "sensor_id, batch_id, passive",
        "IOT_OBSERVATION_RETENTION_DAYS (14 d)",
        "RLS; minimised header fields only"
    ),
    e!(
        "Classification",
        "ZTE-IOTDATA-153136",
        "assets.classification; classification_history",
        "asset_id + at",
        T,
        "history rows on change",
        "ruleset_hash, classifier_version, source",
        "history 400 d",
        "RLS"
    ),
    e!(
        "ClassificationEvidence",
        "ZTE-IOTDATA-153137",
        "classification.evidence (per decision)",
        "rule_id + fact",
        T,
        "with classification",
        "rule origin, weight, fact source",
        "with classification",
        "RLS"
    ),
    e!("Site", "ZTE-IOTDATA-153138", "sites", "uuid v7", T, "soft delete with dependents check", "created_by/updated_by", "until deleted", "RLS; audit"),
    e!(
        "Sensor",
        "ZTE-IOTDATA-153139",
        "sensors (+ platform node)",
        "uuid v7; node_id",
        TS,
        "pending/active; soft delete",
        "node enrolment",
        "until deleted",
        "RLS; node credentials held by the platform"
    ),
    e!(
        "ProtocolObservation",
        "ZTE-IOTDATA-153140",
        "protocol_stats; observations.signals",
        "(bucket, protocol, operation)",
        TS,
        "hourly rollup",
        "sensor statistics",
        "history 400 d",
        "RLS; no values or payloads"
    ),
    e!("FlowObservation", "ZTE-IOTDATA-153141", "flow_rollups", "(asset, bucket, peer, transport, port, direction)", T, "hourly rollup", "sensor flows", "history 400 d", "RLS"),
    e!("PeerRelationship", "ZTE-IOTDATA-153142", "graph_edges", "(from_node, to_node)", T, "first_seen/last_seen", "flows", "history 400 d", "RLS"),
    e!("DependencyEdge", "ZTE-IOTDATA-153143", "graph_edges (client -> server direction)", "(from_node, to_node)", T, "first_seen/last_seen", "flows", "history 400 d", "RLS"),
    e!(
        "FirmwareRecord",
        "ZTE-IOTDATA-153144",
        "firmware_records",
        "(asset_id, firmware)",
        T,
        "first_seen/last_seen",
        "protocol identity, LLDP/CDP, override",
        "life of asset",
        "RLS"
    ),
    e!(
        "VulnerabilityContext",
        "ZTE-IOTDATA-153145",
        "findings (kind vulnerability, end_of_life)",
        "uuid v7; (asset_id, key)",
        T,
        "open/acknowledged/resolved",
        "feed name/version, CPE",
        "life of asset",
        "RLS"
    ),
    e!("RiskScore", "ZTE-IOTDATA-153146", "assets.risk; risk_history", "asset_id + at", T, "history rows on change", "model_version", "history 400 d", "RLS"),
    e!("RiskFactor", "ZTE-IOTDATA-153147", "assets.risk.factors; risk_history.factors", "factor key", T, "with score", "reasons", "with score", "RLS"),
    e!("Segment", "ZTE-IOTDATA-153148", "zones", "uuid v7; key", T, "soft delete with dependents check", "created_by/updated_by", "until deleted", "RLS; audit"),
    e!(
        "SegmentationPolicy",
        "ZTE-IOTDATA-153149",
        "platform policy sets (iot.segmentation) + device_groups",
        "policy_set_id/revision; group uuid",
        T,
        "platform change workflow",
        "approvals, revisions",
        "platform retention",
        "platform RBAC, approvals"
    ),
    e!(
        "AccessRule",
        "ZTE-IOTDATA-153150",
        "platform policy sets (iot.remote_access); access_requests",
        "rule id; request uuid",
        T,
        "pending/approved/denied/expired/revoked/completed",
        "decided_by, approval_id",
        "history 400 d",
        "RLS; audit"
    ),
    e!("TemporaryException", "ZTE-IOTDATA-153151", "exceptions", "uuid v7", T, "pending/approved/denied/revoked, expiry", "approval_id, decided_by", "until deleted", "RLS; audit"),
    e!("VendorPrincipal", "ZTE-IOTDATA-153152", "vendor_principals", "uuid v7", T, "enabled, expires_at", "created_by", "until deleted; erasable", "RLS; privacy erase"),
    e!(
        "RemoteAccessSession",
        "ZTE-IOTDATA-153153",
        "remote_sessions",
        "uuid v7",
        T,
        "active/ended (end_reason)",
        "request_id, broker session, recording digest",
        "history 400 d",
        "RLS; recording content with the broker"
    ),
    e!(
        "Anomaly",
        "ZTE-IOTDATA-153154",
        "anomalies",
        "uuid v7; open (asset, key)",
        T,
        "open/acknowledged/learned/false_positive/resolved",
        "evidence, baseline version",
        "history 400 d",
        "RLS"
    ),
    e!(
        "ThreatCorrelation",
        "ZTE-IOTDATA-153155",
        "threat_indicators + anomalies (threat_intel_match)",
        "indicator; anomaly uuid",
        T,
        "expires_at",
        "indicator source",
        "until expiry",
        "RLS"
    ),
    e!("AssetChangeEvent", "ZTE-IOTDATA-153156", "asset_changes", "uuid v7", T, "append-only", "actor", "history 400 d", "RLS; immutable"),
    e!(
        "TelemetryEvent",
        "ZTE-IOTDATA-153157",
        "log_outbox -> platform log store (iot_* typed log types)",
        "event_id",
        T,
        "outbox until shipped",
        "log schema version",
        "platform log retention",
        "typed attributes; no payloads"
    ),
    e!("Investigation", "ZTE-IOTDATA-153158", "investigations", "uuid v7", T, "open/in_progress/closed", "created_by/assignee", "until deleted", "RLS; audit"),
    e!("Evidence", "ZTE-IOTDATA-153159", "evidence; acceptance_runs", "uuid v7 + sha256", T, "append-only", "created_by, sha256", "history 400 d", "RLS; immutable"),
    e!(
        "ConfigRevision",
        "ZTE-IOTDATA-153160",
        "config_revisions",
        "revision number + content hash",
        T,
        "active flag; rollback",
        "created_by, note",
        "history 400 d",
        "RLS; hash-verified on the edge"
    ),
];

#[cfg(test)]
mod tests {
    #[test]
    fn every_canonical_entity_is_described() {
        assert_eq!(super::ENTITIES.len(), 28);
        for (i, e) in super::ENTITIES.iter().enumerate() {
            assert_eq!(e.requirement, format!("ZTE-IOTDATA-{}", 153133 + i));
        }
    }
}
