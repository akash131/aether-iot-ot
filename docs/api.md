# API

Base path `/api/v1` on the service (`:8096`), or through the platform
gateway at `<platform>/svc/iot/api/v1`. Authentication: platform-issued
bearer tokens (administrators, API clients, services, nodes). Every
administrative route requires the tenant entitlement `iot` and a
`policy.iot:*` permission; node actors are refused on administrative
routes, administrators on node routes.

Conventions: `{data, meta}` envelopes (`meta.request_id`,
`meta.next_cursor`); RFC 9457 problems (`application/problem+json`, stable
`code`, field `errors`); `If-Match: "v<version>"` on `PATCH`/`DELETE`
(`428` when missing, `412` when stale); `Idempotency-Key` on `POST` (replays
the first response); cursor pagination (`limit` ≤ 1000, `cursor`); `ETag`
and `If-None-Match` on node snapshots; `traceparent` propagated.

Permissions: `read` for GET, `create`, `update`, `delete` for mutations,
`activate` for approvals, rollouts, rollbacks and other decisions that
change enforcement.

## Configuration resources

Standard list (`GET`, filters, `q` search, `sort`, cursor), create
(`POST`), get, update (`PATCH` with `If-Match`), delete (soft, refused while
dependents exist). Console metadata for all of them:
`GET /api/v1/meta/resources` (also lists dashboards and wizards).

| Resource | Path | Key fields |
|---|---|---|
| Sites | `/sites` | `name`*, `region`, `address`, `timezone`, `criticality` 1–5, `contact`, `tags`, `branch_site_id`, `data_region` |
| Sensors | `/sensors` | `name`*, `site_id`*, `kind` (`edge_appliance`, `span_port`, `tap`, `virtual`, `branch_edge`), `node_id` (platform node), `capture`, `enforcement` |
| Zones | `/zones` | `name`*, `key` (immutable), `security_level` 1–4, `mode` (`observe`, `simulate`, `enforce`), `safety_critical`, `site_id` |
| Device groups | `/device-groups` | `name`*, `key`, `priority`, `match` {`device_types`, `categories`, `vendors`, `model` glob, `sites`, `tags`, `risk_levels`}, `zone_id`, `privileged`, `min_confidence` |
| Classification rules | `/classification-rules` | `name`*, `source`* (`oui`, `dhcp`, `dns`, `http`, `mdns`, `ssdp`, `lldp`, `cdp`, `tls`, `tcp`, `service`, `protocol`, `protocol_identity`, `behaviour`, `asserted`), `field`*, `match` (`exact`, `prefix`, `suffix`, `contains`, `glob`), `pattern`*, `device_type`, `vendor`, `model`, `os`, `weight`, `enabled` |
| Vendor principals | `/vendor-principals` | `name`*, `company`*, `email`*, `expires_at`* (≤ 1 year), `enabled`, `allowed_group_ids`, `max_session_minutes`, `require_mfa` |
| Remote targets | `/remote-targets` | `name`*, `asset_id`, `console_id` (Private Access privileged console), `protocols` (`https`, `rdp`, `ssh`, `vnc`…), `host`, `port`, `require_approval` |
| Exceptions | `/exceptions` | created by `POST /exceptions` (below); read/update/delete through the resource routes |
| Assertions | `/assertions` | `name`*, `expression`* (inventory expression language), `severity`, `enabled` |
| Saved views | `/saved-views` | `name`*, `resource`*, `query`, `filters`, `columns`, `shared` |
| Threat indicators | `/threat-indicators` | `indicator`*, `kind` (`ip`, `domain`), `source`, `severity`, `expires_at` |
| Investigations | `/investigations` | `name`*, `status`, `severity`, `asset_ids`, `anomaly_ids`, `assignee`, `notes` |
| Settings | `/settings` | `name` (`active_queries`, `risk_tuning`, `remote_access`, `learning`, `retention`, `health_thresholds`, `classification`), `value` (validated per name) |
| Rollouts | `/rollouts` | `name`*, `zone_ids`*, `target_mode`*, `stages`* (1–10 × `{zone_ids, min_hours}`) |

\* required on create.

## Inventory

| Method | Path | Description |
|---|---|---|
| GET | `/assets` | Inventory; filters `device_type`, `category`, `risk_level`, `tier`, `lifecycle`, `ip`, `mac`, `vendor`, `site_id`, `zone_id`, `group_id`, `quarantined`, `protocol`, `min_risk`, `q` (full text, IP, MAC); `sort` `priority` (default, descending), `risk_score`, `last_seen`, `first_seen` (descending), `confidence`, `name` (ascending) |
| GET | `/assets/{id}` | Asset with classification, risk, assignment, identities count |
| PATCH | `/assets/{id}` | Business context: `name`, `owner`, `business_unit`, `criticality`, `location`, `tags`, `notes`, `scanner`, `engineering_station`, `pinned_group_ids` |
| GET | `/assets/{id}/classification` | Explanation: dimensions with confidence and alternatives, evidence (rule, fact, weight, origin), conflicts, classifier version, history |
| PUT / DELETE | `/assets/{id}/override` | Classification override `{device_type, vendor, model, os, firmware, reason}` (wins over rules; audited) |
| GET | `/assets/{id}/risk` | Score, level, impact, priority, factors with reasons, model version, history |
| GET | `/assets/{id}/findings`, `/anomalies`, `/timeline`, `/peers`, `/flows`, `/identities` | Sub-lists |
| GET | `/assets/{id}/baseline` | Network/process modes, edges, value ranges, allow-list, snapshots |
| POST | `/assets/{id}/baseline/{complete,reset,relearn-process}` | Baseline actions (a snapshot is taken first) |
| GET | `/assets/{id}/baseline/snapshots/{sid}/diff` | Edges added/removed, operation classes raised, value ranges changed |
| POST / DELETE | `/assets/{id}/quarantine` | Quarantine `{reason}` / release |
| POST | `/assets/{id}/decommission` | Decommission: groups, zone, exceptions, remote targets and requests cleaned up |
| POST | `/assets/{id}/lifecycle` | Lifecycle transition `{state, reason}` (state machine enforced) |
| POST | `/assets/merge` | `{into, from: [ids], reason}` |
| POST | `/assets/{id}/split` | `{keys: [{key_type, value}], reason}` → new asset |
| GET | `/assets/export` | CSV (default) or `format=json`, same filters as the list (≤ 100 000 rows) |
| POST | `/assets/import` | `{assets: [{mac, ip, hostname, serial, device_type, vendor, model, …}]}` (≤ 5000; asserted identity) |
| GET | `/inventory/summary` | Counts by type, category, risk, tier, lifecycle, site |
| GET | `/search?q=` | Assets, findings, anomalies |

## Findings, anomalies, alerts, active queries

| Method | Path | Description |
|---|---|---|
| GET | `/findings` | `kind` (`vulnerability`, `end_of_life`, `default_credentials`, `cleartext_credentials`, `insecure_protocol`, …), `status`, `min_severity`, `asset_id`, `known_exploited` |
| POST | `/findings/{id}/{acknowledge,resolve,reopen}` | `acknowledge` requires `{reason}` (risk acceptance) |
| GET | `/vulnerability-feed` | Feed name, version, age, advisory count |
| POST | `/vulnerability-feed/refresh` | Reload from `IOT_VULN_FEED_URL` (validated before swap) |
| GET | `/vulnerability-feed/lookup?vendor=&model=&firmware=` | Advisories, end of life, CPE |
| GET | `/anomalies` | `status`, `kind`, `asset_id`, `min_severity` |
| POST | `/anomalies/{id}/{acknowledge,resolve,false_positive,learned}` | `learned` adds the behaviour to the baseline |
| GET | `/alerts` / POST `/alerts/{id}/{acknowledge,resolve}` | De-duplicated alerts (anomaly, identity, firmware, sensor) |
| GET / POST | `/active-queries` | Plan `{kind, target_ids}`: per-target decision (enablement, blackout, restrictions, attempts, approval); `409 nothing_allowed` with the plan when nothing may run |
| POST | `/active-queries/{id}/{approve,cancel}` | Approval (a second administrator) / cancel |

## Segmentation

| Method | Path | Description |
|---|---|---|
| POST | `/segmentation/decide` | `{source_asset_id \| source_ip, destination_asset_id \| destination_ip, protocol, operation_class, operation, port, internet, at, ruleset?}` → verdict (`enforced`, `policy_action`, `mode`, rule, exception, reason, revision/hash) and the flow context; `ruleset` evaluates a draft |
| POST | `/segmentation/simulate` | `{hours, ruleset?}` → verdicts for observed flows, counts by action, newly blocked conduits |
| GET | `/segmentation/recommendations?group_id=` | Recommended `iot.segmentation` rule set from high-confidence baselines |
| POST | `/segmentation/assign-preview` | Groups and zone a device would get |
| GET | `/segmentation/conduits` | Zone-to-zone communication with protocols and highest operation class |
| GET | `/segmentation/snapshot` | The snapshot the edges receive |
| GET | `/config-revisions` / POST `/config-revisions/{rev}/rollback` | Recorded configuration revisions; rollback restores zones and groups |
| POST | `/exceptions` | `{name, justification, source_asset_id \| source_group_id, destination_asset_id \| destination_group_id, protocol, port, max_op, starts_at, expires_at}` (≤ 30 days); pending until approved; platform approval created when configured |
| POST | `/exceptions/{id}/{approve,deny,revoke}` | The requester cannot approve |
| POST | `/rollouts/{id}/{start,advance,rollback}` | Staged zone-mode changes |

## Privileged remote access

| Method | Path | Description |
|---|---|---|
| GET / POST | `/access-requests` | Create `{target_id, vendor_principal_id?, requester_email?, protocol, window_start, window_end, justification (≥ 10 chars), ticket}` → `{request, outcome (pending_approval, approved_by_policy, denied_by_policy), approval_id}` |
| GET | `/access-requests/{id}` | Request with sessions |
| POST | `/access-requests/{id}/{approve,deny,revoke,cancel}` | Local decisions (the requester cannot approve); cancel withdraws the platform approval |
| POST | `/access-requests/{id}/sessions` | Start a session inside the approved window → `{session_id, expires_at, launch: {console_id, grant_ref}}` |
| GET | `/remote-sessions`, `/remote-sessions/{id}` | Sessions with end reason and recording metadata |
| POST | `/remote-sessions/{id}/{activity,end,terminate}` | Activity heartbeat, end, terminate (`activate`) |
| PUT | `/remote-sessions/{id}/recording` | `{recording_id, sha256, size_bytes, duration_ms, stored_by}` |

## Operations

| Method | Path | Description |
|---|---|---|
| GET | `/dashboards/{overview,risk,ot-activity,remote-access}` | Dashboard data |
| GET | `/reports/{inventory,risk,vulnerabilities,anomalies,remote_access,segmentation}` | JSON or `format=csv` |
| GET | `/graph`, `/graph/dependencies?asset_id=` | Communication graph; dependencies and dependents |
| GET | `/status`, `/diagnostics`, `/integrations` | Service state, queues, latency, platform and peer health |
| GET | `/failure-modes`, `/capabilities`, `/schemas`, `/taxonomy`, `/protocols` | Catalogues |
| GET | `/events` | Recent product events |
| POST | `/assertions/run`, GET `/assertions/{id}/violations` | Evaluate assertions |
| GET / POST | `/acceptance/runs`, GET `/acceptance/runs/{id}` | Run the acceptance matrix; evidence with SHA-256 |
| GET / POST | `/investigations/{id}/evidence`, GET `/investigations/{id}/timeline` | Hashed, append-only evidence |
| POST | `/classification/learn` | Learn TLS/DHCP rules from confidently classified devices |
| POST | `/privacy/erase` | `{email}` erase a vendor principal's personal data |

## Node APIs (edge appliance)

Token: platform node token (`act=node`, node kind `service_edge`,
`private_edge` or `branch_connector`); the node must be bound to a sensor.

| Method | Path | Description |
|---|---|---|
| POST | `/node/observations` | `{batch_id, observations: [...], stats}` (≤ limits; 429 under backpressure; duplicate batch ids return the first outcome) |
| GET | `/node/snapshot` | Site snapshot with `content_hash`, `revision`, `enforcement`; `ETag` / `If-None-Match` |
| POST | `/node/status` | Health, failure modes, config age |
| POST | `/node/decisions` | Aggregated verdict counts; `quarantine` actions applied |
| POST | `/node/active-queries/{id}/results` | `{results, observations}` (non-passive observations) |

Local edge API (`IOT_EDGE_ADMIN_BIND`, bearer `IOT_EDGE_ADMIN_TOKEN`):
`GET /health/live`, `GET /health/ready`, `GET /metrics`, `GET /status`,
`POST /v1/decide {src_ip, dst_ip, protocol, operation_class, port}`,
`GET /v1/nftables`, `POST /actions/{resync,flush}`.

## Platform hooks

| Method | Path | Description |
|---|---|---|
| POST | `/policy-hooks/references` | `{policy_type, ref_type (iot.device_group, iot.zone, iot.site, iot.vendor_principal, iot.device), ids}` → `{missing}` |
| POST | `/policy-hooks/simulate` | `{policy_type, context}` → `{context}` enriched with device groups, zone, type, category, risk, confidence for `source.ip`/`destination.ip` or `.device` |

## Policy types

* `iot.segmentation` (default action `alert`) — operands per side
  `source.*` / `destination.*`: `device_group` (multi, ref
  `iot.device_group`), `zone`, `site`, `device`, `device_type`,
  `device_category`, `risk_level` (freshness 1 h), `confidence_tier`
  (freshness 24 h), `quarantined`, `ip`; plus `network.protocol`,
  `network.operation_class`, `network.operation`, `destination.port`,
  `network.internet`, `time`. Actions `allow`, `alert`, `block`,
  `quarantine` (owned by this product).
* `iot.remote_access` (default `deny`) — `user.id`, `user.groups`,
  `iot.vendor`, `source.ip`, `source.country`, `risk.level`,
  `remote.protocol`, `access.approved`, `access.window_active`,
  `access.mfa`, `time` and the target side `destination.*`; actions
  `allow` (`max_minutes`, `record`), `require_approval`, `deny`.
* `iot.active_query` (default `deny`) — `query.kind`, `query.risk`,
  target group/zone/site/type/category, `destination.safety_sensitive`,
  `time`; actions `allow`, `require_approval`, `deny`.
* `firewall.network` extension — operands `iot.source_device_group`,
  `iot.destination_device_group`, `iot.source_zone`,
  `iot.destination_zone`, `iot.destination_device_type`,
  `iot.destination_device_category`, `iot.source_risk_level`,
  `iot.destination_risk_level`, `iot.operation_class`; action
  `iot_quarantine`. Devices are resolved by address through the identity
  bindings this product publishes to Aether Firewall.

## Log types

| Log type | Attributes |
|---|---|
| `iot_discovery` | `asset_id`, `mac`, `ip`, `device_type`, `category`, `vendor`, `model`, `confidence`, `site_id`, `sensor_id`, `event` |
| `iot_anomaly` | `asset_id`, `anomaly_id`, `kind`, `severity`, `device_type` |
| `iot_risk` | `asset_id`, `score`, `level`, `previous_level`, `priority` |
| `iot_flow` | `asset_id`, `peer_ip`, `port`, `transport`, `protocol`, `max_op`, `outbound`, `bytes` |
| `iot_finding` | `asset_id`, `finding_id`, `kind`, `key`, `severity` |
| `iot_decision` | `node_id`, rule, enforced, policy action, mode, source/destination asset, protocol, operation class, count |
| `iot_remote_access` | `request_id`, `event`, `session_id`, `target_id`, vendor |

Risk signals: `POST /api/v1/signals` with `subject_type: workload`,
`subject_name: iot:<device name>`, `source: aether-iot-ot`, `category:
iot_device_risk`, score 0–100, confidence, TTL 24 h and the factors.
