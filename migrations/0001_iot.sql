-- Aether IoT/OT Security product schema (ZTE-IOTDATA-153133..153160
-- canonical schemas; ZTE-IOT section 110 Data Schemas).
--
-- Every table is tenant-scoped (tenant_id NOT NULL) and protected by the
-- standard row-level security policy (FORCE). Administrator-editable
-- resources carry the kit's standard columns (version, timestamps, actors,
-- soft delete). Evidence tables are append-only.

-- ------------------------------------------------------------------ resources

-- Site (ZTE-IOTDATA-153138; section 3 Site And Sensor Topology).
CREATE TABLE sites (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    region text,
    address text,
    timezone text,
    criticality integer NOT NULL DEFAULT 3,
    contact text,
    tags text[] NOT NULL DEFAULT '{}',
    branch_site_id text,
    data_region text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX sites_name ON sites (tenant_id, lower(name)) WHERE deleted_at IS NULL;

-- Sensor / collector (ZTE-IOTDATA-153139; section 117).
CREATE TABLE sensors (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    site_id uuid NOT NULL REFERENCES sites (id),
    kind text NOT NULL DEFAULT 'edge_appliance',
    node_id text,
    description text,
    capture jsonb NOT NULL DEFAULT '{}',
    enforcement boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'pending',
    last_seen_at timestamptz,
    software_version text,
    health jsonb NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX sensors_name ON sensors (tenant_id, lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX sensors_node ON sensors (tenant_id, node_id) WHERE deleted_at IS NULL AND node_id IS NOT NULL;

-- Segment / zone (ZTE-IOTDATA-153148; section 75 zones and conduits).
CREATE TABLE zones (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    key text NOT NULL,
    description text,
    security_level integer NOT NULL DEFAULT 2,
    mode text NOT NULL DEFAULT 'observe',
    safety_critical boolean NOT NULL DEFAULT false,
    site_id uuid REFERENCES sites (id),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX zones_key ON zones (tenant_id, key) WHERE deleted_at IS NULL;

-- Device groups referenced by segmentation policy (ZTE-IOTDATA-153149).
CREATE TABLE device_groups (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    key text NOT NULL,
    description text,
    priority integer NOT NULL DEFAULT 0,
    match jsonb NOT NULL DEFAULT '{}',
    zone_id uuid REFERENCES zones (id),
    privileged boolean NOT NULL DEFAULT false,
    min_confidence double precision NOT NULL DEFAULT 0,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX device_groups_key ON device_groups (tenant_id, key) WHERE deleted_at IS NULL;

-- Tenant classification rules (custom and learned).
CREATE TABLE classification_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    source text NOT NULL,
    field text NOT NULL,
    match text NOT NULL DEFAULT 'exact',
    pattern text NOT NULL,
    device_type text,
    vendor text,
    model text,
    os text,
    weight double precision NOT NULL DEFAULT 0.8,
    enabled boolean NOT NULL DEFAULT true,
    origin text NOT NULL DEFAULT 'custom',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);

-- Vendor principal (ZTE-IOTDATA-153152).
CREATE TABLE vendor_principals (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    company text NOT NULL,
    email text NOT NULL,
    phone text,
    expires_at timestamptz NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    allowed_group_ids uuid[] NOT NULL DEFAULT '{}',
    max_session_minutes integer NOT NULL DEFAULT 240,
    require_mfa boolean NOT NULL DEFAULT true,
    notes text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX vendor_principals_email ON vendor_principals (tenant_id, lower(email)) WHERE deleted_at IS NULL;

-- Remote access targets: OT assets reachable through privileged consoles.
CREATE TABLE remote_targets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    asset_id uuid,
    console_id text,
    protocols text[] NOT NULL DEFAULT '{https}',
    host text,
    port integer,
    require_approval boolean NOT NULL DEFAULT true,
    description text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);

-- Temporary segmentation exceptions (ZTE-IOTDATA-153151).
CREATE TABLE exceptions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    justification text NOT NULL,
    source_asset_id uuid,
    destination_asset_id uuid,
    source_group_id uuid,
    destination_group_id uuid,
    protocol text,
    port integer,
    max_op text,
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'pending_approval',
    approval_id uuid,
    decided_by text,
    decided_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE INDEX exceptions_active ON exceptions (tenant_id, state, expires_at);

-- Inventory assertions (AE-IOT-0011).
CREATE TABLE assertions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    expression text NOT NULL,
    severity integer NOT NULL DEFAULT 5,
    enabled boolean NOT NULL DEFAULT true,
    description text,
    last_run_at timestamptz,
    violations integer NOT NULL DEFAULT 0,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);

-- Saved views / presets (AE-IOT-0014).
CREATE TABLE saved_views (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    resource text NOT NULL,
    query text,
    filters jsonb NOT NULL DEFAULT '{}',
    columns text[] NOT NULL DEFAULT '{}',
    shared boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);

-- Threat indicators (ZTE-IOTDATA-153155 ThreatCorrelation inputs; sections 67, 68).
CREATE TABLE threat_indicators (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    indicator text NOT NULL,
    kind text NOT NULL DEFAULT 'ip',
    source text NOT NULL DEFAULT 'manual',
    severity integer NOT NULL DEFAULT 8,
    expires_at timestamptz,
    description text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX threat_indicators_key ON threat_indicators (tenant_id, lower(indicator)) WHERE deleted_at IS NULL;

-- Investigation (ZTE-IOTDATA-153158; sections 104, 132).
CREATE TABLE investigations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    status text NOT NULL DEFAULT 'open',
    severity integer NOT NULL DEFAULT 5,
    asset_ids uuid[] NOT NULL DEFAULT '{}',
    anomaly_ids uuid[] NOT NULL DEFAULT '{}',
    assignee text,
    notes text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);

-- Tenant settings documents (active queries, risk tuning, remote access
-- limits, learning policy, retention, thresholds).
CREATE TABLE settings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    value jsonb NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX settings_name ON settings (tenant_id, name) WHERE deleted_at IS NULL;

-- Staged rollouts of zone enforcement modes (section 131).
CREATE TABLE rollouts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    zone_ids uuid[] NOT NULL DEFAULT '{}',
    target_mode text NOT NULL,
    stages jsonb NOT NULL DEFAULT '[]',
    state text NOT NULL DEFAULT 'draft',
    current_stage integer NOT NULL DEFAULT 0,
    previous_modes jsonb NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);

-- ------------------------------------------------------------------ inventory

-- DeviceAsset + DeviceIdentity + Classification + RiskScore (ZTE-IOTDATA-153133/134/136/146).
CREATE TABLE assets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text,
    site_id uuid REFERENCES sites (id),
    mac text,
    ip text,
    hostname text,
    serial text,
    client_id text,
    tls_fingerprint text,
    randomized_mac boolean NOT NULL DEFAULT false,
    vlan integer,
    identity_strength text,
    device_type text NOT NULL DEFAULT 'unknown',
    category text NOT NULL DEFAULT 'unknown',
    vendor text,
    model text,
    os text,
    firmware text,
    confidence double precision NOT NULL DEFAULT 0,
    tier text NOT NULL DEFAULT 'low',
    classification jsonb NOT NULL DEFAULT '{}',
    classification_override jsonb NOT NULL DEFAULT '{}',
    signals jsonb NOT NULL DEFAULT '[]',
    protocols text[] NOT NULL DEFAULT '{}',
    services text[] NOT NULL DEFAULT '{}',
    lifecycle text NOT NULL DEFAULT 'discovered',
    quarantined boolean NOT NULL DEFAULT false,
    quarantine_reason text,
    scanner boolean NOT NULL DEFAULT false,
    engineering_station boolean NOT NULL DEFAULT false,
    group_ids uuid[] NOT NULL DEFAULT '{}',
    pinned_group_ids uuid[] NOT NULL DEFAULT '{}',
    zone_id uuid,
    assignment jsonb NOT NULL DEFAULT '{}',
    risk_score integer NOT NULL DEFAULT 0,
    risk_level text NOT NULL DEFAULT 'low',
    impact integer NOT NULL DEFAULT 0,
    priority integer NOT NULL DEFAULT 0,
    risk jsonb NOT NULL DEFAULT '{}',
    risk_evaluated_at timestamptz,
    owner text,
    business_unit text,
    criticality integer,
    location text,
    tags text[] NOT NULL DEFAULT '{}',
    notes text,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    last_sensor_id uuid,
    merged_into uuid,
    decommissioned_at timestamptz,
    search tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', coalesce(name, '') || ' ' || coalesce(hostname, '') || ' ' || coalesce(vendor, '') || ' ' || coalesce(model, '') || ' ' || coalesce(device_type, '') || ' ' || coalesce(ip, '') || ' ' || coalesce(mac, '') || ' ' || coalesce(serial, ''))
    ) STORED,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    deleted_at timestamptz
);
CREATE INDEX assets_mac ON assets (tenant_id, mac) WHERE deleted_at IS NULL AND merged_into IS NULL;
CREATE INDEX assets_serial ON assets (tenant_id, serial) WHERE serial IS NOT NULL AND merged_into IS NULL;
CREATE INDEX assets_ip ON assets (tenant_id, site_id, ip) WHERE merged_into IS NULL;
CREATE INDEX assets_hostname ON assets (tenant_id, site_id, lower(hostname)) WHERE hostname IS NOT NULL;
CREATE INDEX assets_type ON assets (tenant_id, category, device_type);
CREATE INDEX assets_risk ON assets (tenant_id, priority DESC, id);
CREATE INDEX assets_search ON assets USING gin (search);
CREATE INDEX assets_groups ON assets USING gin (group_ids);

-- Identity keys observed per asset (dedup, merge/split history).
CREATE TABLE asset_identities (
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL REFERENCES assets (id),
    key_type text NOT NULL,
    value text NOT NULL,
    site_id uuid,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, asset_id, key_type, value)
);
CREATE INDEX asset_identities_value ON asset_identities (tenant_id, key_type, value);

-- AssetChangeEvent (ZTE-IOTDATA-153156; section 97).
CREATE TABLE asset_changes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    kind text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}',
    actor text NOT NULL DEFAULT 'system'
);
CREATE INDEX asset_changes_asset ON asset_changes (tenant_id, asset_id, at DESC);

-- Classification history and evidence (ZTE-IOTDATA-153136/153137).
CREATE TABLE classification_history (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    device_type text NOT NULL,
    confidence double precision NOT NULL,
    source text NOT NULL,
    ruleset_hash text NOT NULL,
    result jsonb NOT NULL
);
CREATE INDEX classification_history_asset ON classification_history (tenant_id, asset_id, at DESC);

-- FirmwareRecord (ZTE-IOTDATA-153144).
CREATE TABLE firmware_records (
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    firmware text NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, asset_id, firmware)
);

-- RiskScore history (ZTE-IOTDATA-153146/153147).
CREATE TABLE risk_history (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    score integer NOT NULL,
    level text NOT NULL,
    factors jsonb NOT NULL DEFAULT '[]',
    model_version text NOT NULL
);
CREATE INDEX risk_history_asset ON risk_history (tenant_id, asset_id, at DESC);

-- DeviceObservation (ZTE-IOTDATA-153135), short retention, minimised.
CREATE TABLE observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid,
    sensor_id uuid,
    batch_id text,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    passive boolean NOT NULL DEFAULT true,
    data jsonb NOT NULL
);
CREATE INDEX observations_asset ON observations (tenant_id, asset_id, observed_at DESC);
CREATE INDEX observations_received ON observations (tenant_id, received_at);

-- Idempotent ingestion batches.
CREATE TABLE ingest_batches (
    tenant_id uuid NOT NULL,
    batch_id text NOT NULL,
    sensor_id uuid,
    received_at timestamptz NOT NULL DEFAULT now(),
    accepted integer NOT NULL DEFAULT 0,
    rejected jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (tenant_id, batch_id)
);

-- Communication baselines and snapshots (section 53; AE-IOT-0013).
CREATE TABLE baselines (
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    data jsonb NOT NULL,
    network_mode text NOT NULL DEFAULT 'learning',
    process_mode text NOT NULL DEFAULT 'learning',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, asset_id)
);
CREATE TABLE baseline_snapshots (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    taken_at timestamptz NOT NULL DEFAULT now(),
    reason text,
    data jsonb NOT NULL
);

-- FlowObservation rollups (ZTE-IOTDATA-153141; section 112 time series).
CREATE TABLE flow_rollups (
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    bucket timestamptz NOT NULL,
    peer_ip text NOT NULL,
    transport text NOT NULL,
    port integer NOT NULL,
    outbound boolean NOT NULL,
    peer_asset_id uuid,
    protocol text,
    max_op text,
    operations text[] NOT NULL DEFAULT '{}',
    packets bigint NOT NULL DEFAULT 0,
    bytes bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, asset_id, bucket, peer_ip, transport, port, outbound)
);
CREATE INDEX flow_rollups_bucket ON flow_rollups (tenant_id, bucket);

-- ProtocolObservation rollups (ZTE-IOTDATA-153140; section 94).
CREATE TABLE protocol_stats (
    tenant_id uuid NOT NULL,
    site_id uuid,
    bucket timestamptz NOT NULL,
    protocol text NOT NULL,
    operation text NOT NULL,
    op_class text NOT NULL,
    events bigint NOT NULL DEFAULT 0,
    errors bigint NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX protocol_stats_key ON protocol_stats (tenant_id, coalesce(site_id, '00000000-0000-0000-0000-000000000000'::uuid), bucket, protocol, operation, op_class);

-- PeerRelationship / DependencyEdge (ZTE-IOTDATA-153142/153143; section 111 graph store).
CREATE TABLE graph_edges (
    tenant_id uuid NOT NULL,
    from_node text NOT NULL,
    to_node text NOT NULL,
    from_asset uuid,
    to_asset uuid,
    protocols text[] NOT NULL DEFAULT '{}',
    ports integer[] NOT NULL DEFAULT '{}',
    max_op text,
    bytes bigint NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, from_node, to_node)
);

-- VulnerabilityContext and exposure findings (ZTE-IOTDATA-153145).
CREATE TABLE findings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    kind text NOT NULL,
    key text NOT NULL,
    title text NOT NULL,
    severity double precision NOT NULL,
    known_exploited boolean NOT NULL DEFAULT false,
    detail jsonb NOT NULL DEFAULT '{}',
    remediation text,
    status text NOT NULL DEFAULT 'open',
    acknowledged_by text,
    acknowledged_at timestamptz,
    ack_reason text,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (tenant_id, asset_id, key)
);
CREATE INDEX findings_status ON findings (tenant_id, status, severity DESC);

-- Anomaly (ZTE-IOTDATA-153154).
CREATE TABLE anomalies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    kind text NOT NULL,
    key text NOT NULL,
    severity double precision NOT NULL,
    title text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'open',
    count integer NOT NULL DEFAULT 1,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    resolved_by text,
    resolved_at timestamptz,
    resolution text
);
CREATE UNIQUE INDEX anomalies_open ON anomalies (tenant_id, asset_id, key) WHERE status = 'open';
CREATE INDEX anomalies_list ON anomalies (tenant_id, status, last_seen DESC);

-- System and policy alerts (failure modes, assertions, rollouts).
CREATE TABLE alerts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    kind text NOT NULL,
    dedup_key text NOT NULL,
    severity integer NOT NULL,
    title text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'open',
    count integer NOT NULL DEFAULT 1,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    forwarded boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX alerts_open ON alerts (tenant_id, dedup_key) WHERE status = 'open';

-- ------------------------------------------------------------------ remote access

-- Access requests (AccessRule instances, ZTE-IOTDATA-153150; sections 86-90).
CREATE TABLE access_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    vendor_principal_id uuid,
    requester_email text NOT NULL,
    requester_admin_id uuid,
    target_id uuid NOT NULL,
    protocol text NOT NULL,
    justification text NOT NULL,
    ticket text,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'pending_approval',
    approval_id uuid,
    decided_by text,
    decided_at timestamptz,
    decision_comment text,
    grant_ref text,
    grant_source text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX access_requests_state ON access_requests (tenant_id, state, window_end);

-- RemoteAccessSession (ZTE-IOTDATA-153153; section 91).
CREATE TABLE remote_sessions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    request_id uuid NOT NULL REFERENCES access_requests (id),
    user_email text NOT NULL,
    client_ip text,
    started_at timestamptz NOT NULL DEFAULT now(),
    last_activity_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    end_reason text,
    terminate_requested boolean NOT NULL DEFAULT false,
    broker_session_id text,
    recording jsonb,
    bytes_in bigint NOT NULL DEFAULT 0,
    bytes_out bigint NOT NULL DEFAULT 0,
    events jsonb NOT NULL DEFAULT '[]'
);
CREATE INDEX remote_sessions_live ON remote_sessions (tenant_id, ended_at);

-- ------------------------------------------------------------------ operations

-- ConfigRevision (ZTE-IOTDATA-153160): zone/group snapshots for edges, rollback.
CREATE TABLE config_revisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    revision bigint NOT NULL,
    hash text NOT NULL,
    snapshot jsonb NOT NULL,
    note text,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    active boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_id, revision)
);

-- Edge node status and capture health (section 117, 134).
CREATE TABLE node_status (
    tenant_id uuid NOT NULL,
    node_id text NOT NULL,
    sensor_id uuid,
    last_report timestamptz NOT NULL DEFAULT now(),
    software_version text,
    config_revision bigint,
    status jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, node_id)
);

-- Edge decision counters (section 92 device access logging).
CREATE TABLE decision_stats (
    tenant_id uuid NOT NULL,
    bucket timestamptz NOT NULL,
    node_id text NOT NULL,
    rule text NOT NULL,
    enforced text NOT NULL,
    count bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, bucket, node_id, rule, enforced)
);

-- Active query jobs (section 5; AE-IOT-0007/0008).
CREATE TABLE active_queries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    kind text NOT NULL,
    target_ids uuid[] NOT NULL,
    state text NOT NULL DEFAULT 'planned',
    plan jsonb NOT NULL DEFAULT '[]',
    approval_id uuid,
    requested_by text,
    results jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Evidence (ZTE-IOTDATA-153159; section 133) and acceptance runs.
CREATE TABLE evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    investigation_id uuid,
    kind text NOT NULL,
    ref text,
    sha256 text NOT NULL,
    data jsonb NOT NULL,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE acceptance_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    software_version text NOT NULL,
    passed integer NOT NULL,
    failed integer NOT NULL,
    sections integer[] NOT NULL DEFAULT '{}',
    results jsonb NOT NULL,
    sha256 text NOT NULL,
    created_by text
);

-- Synchronisation cursors with the platform and peers.
CREATE TABLE sync_state (
    tenant_id uuid NOT NULL,
    key text NOT NULL,
    value jsonb NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key)
);

-- TelemetryEvent outbox to the platform log store (ZTE-IOTDATA-153157).
CREATE TABLE log_outbox (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL,
    record jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text
);
CREATE INDEX log_outbox_due ON log_outbox (next_attempt_at, id);

-- Risk signals to the platform.
CREATE TABLE signal_outbox (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL,
    signal jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text
);
CREATE INDEX signal_outbox_due ON signal_outbox (next_attempt_at, id);

-- Row-level security on every table.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sites', 'sensors', 'zones', 'device_groups', 'classification_rules', 'vendor_principals', 'remote_targets', 'exceptions', 'assertions', 'saved_views', 'threat_indicators', 'investigations', 'settings', 'rollouts', 'assets', 'asset_identities', 'asset_changes', 'classification_history', 'firmware_records', 'risk_history', 'observations', 'ingest_batches', 'baselines', 'baseline_snapshots', 'flow_rollups', 'protocol_stats', 'graph_edges', 'findings', 'anomalies', 'alerts', 'access_requests', 'remote_sessions', 'config_revisions', 'node_status', 'decision_stats', 'active_queries', 'evidence', 'acceptance_runs', 'sync_state', 'log_outbox', 'signal_outbox'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = aether_tenant() OR aether_rls_bypass()) WITH CHECK (tenant_id = aether_tenant() OR aether_rls_bypass())', t);
    END LOOP;
END $$;

-- Append-only evidence.
CREATE TRIGGER asset_changes_immutable BEFORE UPDATE OR DELETE ON asset_changes FOR EACH ROW EXECUTE FUNCTION aether_forbid_mutation();
CREATE TRIGGER evidence_immutable BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION aether_forbid_mutation();
CREATE TRIGGER acceptance_runs_immutable BEFORE UPDATE OR DELETE ON acceptance_runs FOR EACH ROW EXECUTE FUNCTION aether_forbid_mutation();
