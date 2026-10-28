//! Capability contracts (ZTE-IOT-*-i1 "define component ownership, trust
//! boundaries, inputs, outputs, dependencies and authoritative state" for
//! each of the 134 capabilities of the IoT/OT volume, sections 2–135).
//!
//! Each capability names the component that owns it, the modules that
//! implement it, its trusted and untrusted inputs, outputs, authoritative
//! state and the acceptance profile (traffic family) used by the
//! acceptance harness. The catalogue is served by
//! `GET /api/v1/capabilities` and rendered in docs/traceability.md.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    /// Passive collector on the edge appliance (untrusted network input).
    EdgeCollector,
    /// Enforcement on the edge appliance.
    EdgeEnforcer,
    /// Control-plane API and pipeline (tenant data, RLS).
    ControlPlane,
    /// Background workers of the control plane.
    Workers,
    /// Engines shared by edge and control plane (pure functions).
    Engines,
    /// Platform-rendered console over this service's metadata and APIs.
    Console,
    /// Deployment and operations.
    Operations,
}

impl Component {
    pub fn inputs(&self) -> (&'static str, &'static str) {
        match self {
            Component::EdgeCollector => {
                ("enrolment credential, verified configuration snapshot", "mirrored frames (pcap spool, TZSP), DHCP/DNS/HTTP/mDNS/LLDP/CDP metadata, industrial protocol payloads")
            }
            Component::EdgeEnforcer => ("verified compiled policy artifacts and zone/group snapshot", "flow decision requests from local enforcement points"),
            Component::ControlPlane => ("platform-signed admin, service and node tokens", "request bodies, observation batches from enrolled nodes, peer product responses"),
            Component::Workers => ("tenant database state (RLS)", "vulnerability feed documents, peer product inventories and approvals"),
            Component::Engines => ("caller-validated typed values", "decoded protocol fields and fingerprint strings"),
            Component::Console => ("metadata and APIs of this service through the platform gateway", "administrator input (validated server-side)"),
            Component::Operations => ("deployment configuration and secrets", "none"),
        }
    }
    pub fn outputs(&self) -> &'static str {
        match self {
            Component::EdgeCollector => "minimised observation batches, protocol telemetry, capture health",
            Component::EdgeEnforcer => "allow/block verdicts with rule, revision and reason; decision logs; nftables rules",
            Component::ControlPlane => "inventory, classifications, risk, findings, anomalies, policies context, audit and outbox events",
            Component::Workers => "re-scored assets, alerts, platform logs, risk signals, approvals, peer integrations",
            Component::Engines => "deterministic results with explanations and stable error codes",
            Component::Console => "screens, dashboards and wizards rendered by the platform",
            Component::Operations => "deployed service, metrics, alerts and runbooks",
        }
    }
    pub fn state(&self) -> &'static str {
        match self {
            Component::EdgeCollector | Component::EdgeEnforcer => "edge state directory (credential 0600, last applied configuration); authoritative copy in the control plane",
            Component::ControlPlane | Component::Workers => "product PostgreSQL database with row-level security per tenant",
            Component::Engines => "stateless",
            Component::Console => "none (platform console)",
            Component::Operations => "deployment manifests",
        }
    }
    pub fn trust_boundary(&self) -> &'static str {
        match self {
            Component::EdgeCollector => "network traffic is untrusted: bounded parsers, no payload retention; the node authenticates to the platform with a credential",
            Component::EdgeEnforcer => "only artifacts whose content hash verifies are applied; unknown context never widens access",
            Component::ControlPlane => "every request authenticated by platform tokens, permission and entitlement checks, tenant isolation by RLS",
            Component::Workers => "system transactions only for cross-tenant claiming; per-tenant work under RLS",
            Component::Engines => "pure functions over validated inputs",
            Component::Console => "server-side authorization on every API call",
            Component::Operations => "secrets from the environment or secret store, never in images",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub section: u16,
    pub name: &'static str,
    pub component: Component,
    pub modules: &'static str,
    /// Acceptance harness traffic profile.
    pub profile: &'static str,
}

macro_rules! c {
    ($s:expr, $n:expr, $c:ident, $m:expr, $p:expr) => {
        Capability { section: $s, name: $n, component: Component::$c, modules: $m, profile: $p }
    };
}

pub const CAPABILITIES: &[Capability] = &[
    c!(2, "IoT/OT Security Architecture", ControlPlane, "iot-core (all engines); iot-service api, pipeline, workers, edge", "modbus"),
    c!(3, "Site And Sensor Topology", ControlPlane, "api/resources.rs (sites, sensors); edge/mod.rs (enrolment)", "modbus"),
    c!(4, "Passive Discovery", EdgeCollector, "iot-core collect.rs; edge/capture.rs", "camera"),
    c!(5, "Active Discovery Safeguards", Engines, "iot-core activeq.rs; api/ingest.rs (active query plans); edge/activeq.rs", "plc_enip"),
    c!(6, "Packet Metadata Collection", EdgeCollector, "iot-core packet.rs, collect.rs", "modbus"),
    c!(7, "Flow-Based Discovery", EdgeCollector, "iot-core collect.rs (flows); pipeline.rs", "modbus"),
    c!(8, "DHCP Fingerprinting", Engines, "iot-core fingerprint/dhcp.rs, classify.rs", "camera"),
    c!(9, "DNS Fingerprinting", Engines, "iot-core fingerprint/dns.rs, classify.rs", "camera"),
    c!(10, "MAC/OUI Intelligence", Engines, "iot-core fingerprint/mod.rs (OuiTable)", "camera"),
    c!(11, "TLS Fingerprinting", Engines, "iot-core fingerprint/tls.rs, classify.rs (learned rules)", "camera"),
    c!(12, "HTTP Fingerprinting", Engines, "iot-core fingerprint/http.rs", "printer"),
    c!(13, "Network Behavior Fingerprinting", Engines, "iot-core classify.rs (behaviour_facts)", "modbus"),
    c!(14, "Multisignal Device Classification", Engines, "iot-core classify.rs; pipeline.rs", "plc_enip"),
    c!(15, "Classification Confidence", Engines, "iot-core classify.rs (confidence, tiers)", "plc_enip"),
    c!(16, "Unknown Device Handling", Engines, "iot-core classify.rs; segmentation.rs (quarantine/observe)", "unknown"),
    c!(17, "Asset Identity Lifecycle", ControlPlane, "iot-core identity.rs, taxonomy.rs (Lifecycle); api/assets.rs", "modbus"),
    c!(18, "Asset Deduplication", ControlPlane, "iot-core identity.rs; pipeline.rs", "modbus"),
    c!(19, "Asset Merge And Split", ControlPlane, "iot-core identity.rs; api/assets.rs (merge, split)", "modbus"),
    c!(20, "Asset Inventory", ControlPlane, "api/assets.rs; migrations (assets)", "modbus"),
    c!(21, "Asset Ownership And Business Context", ControlPlane, "api/assets.rs (owner, criticality, tags, location)", "modbus"),
    c!(22, "Device Taxonomy", Engines, "iot-core taxonomy.rs", "modbus"),
    c!(23, "Enterprise IoT Devices", Engines, "iot-core classify.rs, taxonomy.rs", "mqtt"),
    c!(24, "Printers And Peripherals", Engines, "iot-core classify.rs, taxonomy.rs", "printer"),
    c!(25, "Cameras And Physical Security", Engines, "iot-core classify.rs, taxonomy.rs", "camera"),
    c!(26, "Building Management Systems", Engines, "iot-core protocols/bacnet.rs, classify.rs", "bacnet"),
    c!(27, "Medical/Clinical Devices", Engines, "iot-core classify.rs (DICOM/HL7 behaviour), taxonomy.rs", "medical"),
    c!(28, "Industrial Control Systems", Engines, "iot-core protocols/*, classify.rs", "s7"),
    c!(29, "PLC Assets", Engines, "iot-core classify.rs; protocols/s7.rs, enip.rs, modbus.rs", "s7"),
    c!(30, "HMI Assets", Engines, "iot-core classify.rs (protocol client roles)", "modbus"),
    c!(31, "SCADA Assets", Engines, "iot-core classify.rs; protocols/dnp3.rs, iec104.rs", "dnp3"),
    c!(32, "Historian Assets", Engines, "iot-core classify.rs; protocols/opcua.rs", "opcua"),
    c!(33, "Engineering Workstations", Engines, "iot-core classify.rs (engineering operations), baseline.rs", "s7"),
    c!(34, "Robotics And Manufacturing", Engines, "iot-core classify.rs, taxonomy.rs; protocols/profinet.rs", "profinet"),
    c!(35, "Retail/POS Devices", Engines, "iot-core classify.rs, taxonomy.rs", "pos"),
    c!(36, "Smart Building Devices", Engines, "iot-core classify.rs, taxonomy.rs", "bacnet"),
    c!(37, "Badge/Access Systems", Engines, "iot-core classify.rs, taxonomy.rs", "badge"),
    c!(38, "Voice/Video Devices", Engines, "iot-core fingerprint/lldp.rs (CDP/LLDP), classify.rs", "voip"),
    c!(39, "Industrial Protocol Parser Framework", Engines, "iot-core protocols/mod.rs", "modbus"),
    c!(40, "Modbus Visibility", Engines, "iot-core protocols/modbus.rs", "modbus"),
    c!(41, "DNP3 Visibility", Engines, "iot-core protocols/dnp3.rs", "dnp3"),
    c!(42, "BACnet Visibility", Engines, "iot-core protocols/bacnet.rs", "bacnet"),
    c!(43, "OPC UA Visibility", Engines, "iot-core protocols/opcua.rs", "opcua"),
    c!(44, "S7 Visibility", Engines, "iot-core protocols/s7.rs", "s7"),
    c!(45, "EtherNet/IP Visibility", Engines, "iot-core protocols/enip.rs", "plc_enip"),
    c!(46, "PROFINET Visibility", Engines, "iot-core protocols/profinet.rs", "profinet"),
    c!(47, "IEC Protocol Visibility", Engines, "iot-core protocols/iec104.rs", "iec104"),
    c!(48, "MQTT Visibility", Engines, "iot-core protocols/mqtt.rs", "mqtt"),
    c!(49, "AMQP Visibility", Engines, "iot-core protocols/amqp.rs", "amqp"),
    c!(50, "SNMP Visibility", Engines, "iot-core protocols/snmp.rs", "snmp"),
    c!(51, "Protocol Parser Hardening", Engines, "iot-core protocols/* (bounds, fuzz tests)", "modbus"),
    c!(52, "Protocol Anomaly Detection", Engines, "iot-core baseline.rs (malformed, errors, mode changes)", "s7"),
    c!(53, "Device Communication Baseline", Engines, "iot-core baseline.rs; workers.rs (learning completion)", "modbus"),
    c!(54, "Peer Relationship Graph", Engines, "iot-core graph.rs; api/assets.rs (peers)", "modbus"),
    c!(55, "Asset Dependency Graph", Engines, "iot-core graph.rs; api/ops.rs (graph)", "opcua"),
    c!(56, "Internet Destination Analysis", Engines, "iot-core graph.rs (internet destinations), baseline.rs (internet anomalies)", "mqtt"),
    c!(57, "Private Application Dependency Analysis", ControlPlane, "iot-core graph.rs; integrations.rs (private access)", "opcua"),
    c!(58, "Device Risk Model", Engines, "iot-core risk.rs; pipeline.rs", "plc_enip"),
    c!(59, "Exposure Risk", Engines, "iot-core risk.rs (exposure), vuln.rs (insecure protocols)", "camera"),
    c!(60, "Behavior Risk", Engines, "iot-core risk.rs (behaviour), baseline.rs", "modbus"),
    c!(61, "Protocol Risk", Engines, "iot-core risk.rs (protocol), vuln.rs", "s7"),
    c!(62, "Identity Confidence Risk", Engines, "iot-core risk.rs (identity)", "unknown"),
    c!(63, "Vulnerability Context Ingestion", Workers, "iot-core vuln.rs (VulnFeed, OfflineFeed); workers.rs (feed refresh)", "plc_enip"),
    c!(64, "CVE/CPE Mapping", Engines, "iot-core vuln.rs (cpe, advisories)", "plc_enip"),
    c!(65, "Firmware/Version Intelligence", Engines, "iot-core vuln.rs (cmp_version), classify.rs (firmware)", "s7"),
    c!(66, "End-Of-Life Device Risk", Engines, "iot-core vuln.rs (end_of_life), risk.rs", "camera"),
    c!(67, "Threat Intelligence Correlation", Workers, "api/resources.rs (threat indicators); iot-core baseline.rs (threat matches)", "mqtt"),
    c!(68, "Malware/C2 Correlation", Workers, "iot-core baseline.rs (threat_intel_match), risk.rs (threat_intel)", "mqtt"),
    c!(69, "Risk Prioritization", Engines, "iot-core risk.rs (impact, priority); api/assets.rs (sort by priority)", "plc_enip"),
    c!(70, "Segmentation Architecture", Engines, "iot-core segmentation.rs, policy.rs", "modbus"),
    c!(71, "Device Segment Assignment", Engines, "iot-core segmentation.rs (assign); pipeline.rs", "modbus"),
    c!(72, "Dynamic Segmentation", ControlPlane, "pipeline.rs (re-assignment on classification/risk change)", "modbus"),
    c!(73, "Quarantine Segment", ControlPlane, "iot-core segmentation.rs; api/assets.rs (quarantine)", "unknown"),
    c!(74, "IoT Microsegmentation", EdgeEnforcer, "iot-core segmentation.rs (decide); edge/enforce.rs", "camera"),
    c!(75, "OT Zone/Conduit Policy", Engines, "iot-core segmentation.rs (zones), graph.rs (conduits); api/resources.rs (zones)", "s7"),
    c!(76, "East-West Device Policy", EdgeEnforcer, "iot-core policy.rs (iot.segmentation), segmentation.rs", "modbus"),
    c!(77, "North-South Device Policy", EdgeEnforcer, "iot-core policy.rs, segmentation.rs", "mqtt"),
    c!(78, "Internet Access Policy", EdgeEnforcer, "iot-core policy.rs (network.internet), segmentation.rs", "mqtt"),
    c!(79, "Private Application Access Policy", ControlPlane, "iot-core policy.rs (iot.remote_access); integrations.rs (private access)", "opcua"),
    c!(80, "Zero Trust Branch Integration", Workers, "integrations.rs (branch inventory); workers.rs", "camera"),
    c!(81, "Branch Enforcement", EdgeEnforcer, "edge/enforce.rs; integrations.rs (firewall identity bindings)", "modbus"),
    c!(82, "Cloud Policy Distribution", EdgeEnforcer, "edge/mod.rs (manifest, artifacts, snapshot); api/ingest.rs (snapshot)", "modbus"),
    c!(83, "Policy Simulation", ControlPlane, "iot-core segmentation.rs (simulate); api/segmentation.rs; api/hooks.rs", "modbus"),
    c!(84, "Policy Activation/Rollback", ControlPlane, "api/segmentation.rs (config revisions, rollback, rollouts); platform change workflow", "modbus"),
    c!(85, "Exception Workflow", ControlPlane, "api/segmentation.rs (exceptions with approvals); iot-core segmentation.rs (Exception)", "modbus"),
    c!(86, "Temporary Access Workflow", ControlPlane, "iot-core remote.rs; api/remote.rs", "remote"),
    c!(87, "Vendor Remote Access", ControlPlane, "api/remote.rs (vendor principals); integrations.rs (private access)", "remote"),
    c!(88, "Third-Party Maintenance Access", ControlPlane, "api/remote.rs; iot-core remote.rs", "remote"),
    c!(89, "Privileged OT Access", ControlPlane, "api/remote.rs; iot-core policy.rs (iot.remote_access)", "remote"),
    c!(90, "Session Approval", Workers, "api/remote.rs; workers.rs (platform approval inbox)", "remote"),
    c!(91, "Session Auditing", ControlPlane, "api/remote.rs (sessions, recordings metadata)", "remote"),
    c!(92, "Device Access Logging", Workers, "pipeline.rs (logs); workers.rs (ship_logs, log schemas)", "modbus"),
    c!(93, "Device Flow Telemetry", EdgeCollector, "iot-core collect.rs; pipeline.rs (flow logs)", "modbus"),
    c!(94, "Protocol Telemetry", EdgeCollector, "iot-core collect.rs (protocol stats); pipeline.rs", "dnp3"),
    c!(95, "Risk Events", Workers, "pipeline.rs (risk events, signals)", "plc_enip"),
    c!(96, "Anomaly Events", Workers, "pipeline.rs (anomalies, alerts)", "s7"),
    c!(97, "Asset Change Events", ControlPlane, "pipeline.rs (asset_changes)", "modbus"),
    c!(98, "IoT/OT Dashboards", Console, "api/mod.rs (MetaDashboard); api/ops.rs (dashboard data)", "modbus"),
    c!(99, "Inventory UI", Console, "api/assets.rs; api/mod.rs (metadata)", "modbus"),
    c!(100, "Device Detail UI", Console, "api/assets.rs (detail, explain, timeline)", "modbus"),
    c!(101, "Risk UI", Console, "api/assets.rs (risk explain); api/ops.rs (risk dashboard)", "plc_enip"),
    c!(102, "Segmentation UI", Console, "api/segmentation.rs; api/mod.rs (wizards)", "modbus"),
    c!(103, "Policy UI", Console, "platform policy editor over iot.* types; api/hooks.rs", "modbus"),
    c!(104, "Investigation UI", Console, "api/ops.rs (investigations, search)", "s7"),
    c!(105, "Search And Reporting", ControlPlane, "api/ops.rs (search, reports, saved views); iot-core assertions.rs", "modbus"),
    c!(106, "IoT/OT APIs", ControlPlane, "api/* (envelopes, problems, pagination, idempotency)", "modbus"),
    c!(107, "Inventory APIs", ControlPlane, "api/assets.rs", "modbus"),
    c!(108, "Policy APIs", ControlPlane, "api/segmentation.rs; api/hooks.rs; platform policy APIs", "modbus"),
    c!(109, "Event APIs", ControlPlane, "api/ops.rs (events); aether-kit outbox relay", "modbus"),
    c!(110, "Data Schemas", ControlPlane, "iot-core schemas.rs; migrations", "modbus"),
    c!(111, "Graph Store", ControlPlane, "iot-core graph.rs; migrations (graph_edges)", "opcua"),
    c!(112, "Time-Series Telemetry Store", ControlPlane, "migrations (telemetry_rollups); pipeline.rs", "modbus"),
    c!(113, "Search Index", ControlPlane, "migrations (search vector index); api/ops.rs (search)", "modbus"),
    c!(114, "Caches And Event Bus", ControlPlane, "state.rs (caches); aether-kit outbox; workers.rs (relay)", "modbus"),
    c!(115, "Secrets And PKI", ControlPlane, "aether-kit crypto Keyring; edge credential 0600; platform node certificates", "modbus"),
    c!(116, "Platform Security", ControlPlane, "aether-kit Ctx (authn/z), RLS, rate limits, security headers", "modbus"),
    c!(117, "Sensor/Collector Security", EdgeCollector, "edge/mod.rs (node tokens, verified artifacts); api/ingest.rs (node kind checks)", "modbus"),
    c!(118, "Privacy And Minimization", Engines, "iot-core collect.rs (no payloads), model.rs (clipping), protocols/snmp.rs (no community); api/ops.rs (retention, erase)", "snmp"),
    c!(119, "Sovereignty", Operations, "config.rs (region pinning); deploy/helm (per-region deployment)", "modbus"),
    c!(120, "Observability", ControlPlane, "telemetry.rs; aether-kit metrics; deploy/observability", "modbus"),
    c!(121, "SRE", Operations, "docs/operations.md; deploy/observability/alerts.yml; iot-core failure.rs", "modbus"),
    c!(122, "HA/DR", Operations, "stateless replicas; deploy/helm (replicas, PDB); edge fail-static", "modbus"),
    c!(123, "Capacity", Operations, "bounded queues and limits (config.rs); load driver (tests/load.rs)", "modbus"),
    c!(124, "Performance", Operations, "tests/load.rs; docs/performance.md", "modbus"),
    c!(125, "Chaos Engineering", Operations, "iot-core failure.rs; tests/resilience.rs (fault injection)", "modbus"),
    c!(126, "Security Testing", Operations, "tests/api.rs (authorization, isolation); CI clippy", "modbus"),
    c!(127, "Protocol Fuzzing", Engines, "iot-core protocols/mod.rs (all_parsers_are_fuzz_safe), packet.rs", "modbus"),
    c!(128, "Device Classification Validation", Engines, "iot-core acceptance.rs (classification corpus)", "plc_enip"),
    c!(129, "Segmentation Certification", Engines, "iot-core acceptance.rs; segmentation.rs (simulate)", "modbus"),
    c!(130, "Industrial Safety Validation", Engines, "iot-core acceptance.rs (safety invariants)", "s7"),
    c!(131, "Fleet/Site Rollout", ControlPlane, "api/segmentation.rs (staged zone mode rollouts); edge upgrades via platform", "modbus"),
    c!(132, "Incident Response", ControlPlane, "api/ops.rs (investigations); api/assets.rs (quarantine)", "s7"),
    c!(133, "Forensics And Evidence", ControlPlane, "api/ops.rs (evidence, acceptance evidence); aether-kit hash-chained audit", "s7"),
    c!(134, "Support Diagnostics", ControlPlane, "api/ops.rs (diagnostics); edge/admin.rs", "modbus"),
    c!(135, "Lifecycle And Decommissioning", ControlPlane, "api/assets.rs (decommission); pipeline.rs", "modbus"),
];

pub fn by_section(s: u16) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|c| c.section == s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_section_has_a_contract() {
        assert_eq!(CAPABILITIES.len(), 134);
        for (i, c) in CAPABILITIES.iter().enumerate() {
            assert_eq!(c.section as usize, i + 2);
            assert!(!c.modules.is_empty());
            assert!(crate::acceptance::PROFILES.contains(&c.profile), "{} uses unknown profile {}", c.name, c.profile);
            let (t, u) = c.component.inputs();
            assert!(!t.is_empty() && !u.is_empty() && !c.component.outputs().is_empty() && !c.component.state().is_empty() && !c.component.trust_boundary().is_empty());
        }
    }
}
