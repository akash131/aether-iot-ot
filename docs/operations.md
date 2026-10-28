# Operations

## Processes

| Command | Purpose |
|---|---|
| `aether-iot serve` | Control-plane API and (unless `IOT_WORKERS=false`) background workers. Registers policy types, the `firewall.network` extension, action owners, log schemas and hooks with the platform at start (retried). |
| `aether-iot edge` | Edge appliance on a site: enrols, collects, ships observations, applies verified configuration, serves the local decision API. |
| `aether-iot migrate` | Applies the kit base schema and `migrations/` and exits (Helm pre-install/upgrade hook). |
| `aether-iot register-policy-types` | Registration only (policy types, extension, action owners, log schemas, hooks). |
| `aether-iot analyze <file.pcap>` | Offline passive analysis of a capture file (prints observations and statistics). |

## Control-plane settings

| Variable | Default | Meaning |
|---|---|---|
| `IOT_BIND` | `0.0.0.0:8096` | Listen address |
| `IOT_DATABASE_URL` | `postgres://aether_iot:aether_iot@localhost:5432/aether_iot` (required in production) | PostgreSQL; the role must be `NOSUPERUSER NOBYPASSRLS` (checked at start in production) |
| `IOT_ENCRYPTION_KEYS` | development key (required in production) | Keyring `1:<base64 32 bytes>[,2:…]`; the last key encrypts, all decrypt |
| `IOT_ENV` | — | `production` enforces the required settings |
| `IOT_DB_MAX_CONNECTIONS` | 20 | Pool size |
| `IOT_RUN_MIGRATIONS` | true | Apply migrations at start (Helm sets false and uses the migrate job) |
| `IOT_WORKERS` | true | Run background workers in this process |
| `IOT_WORKER_INTERVAL_MS` | 5000 | Worker cycle (shipping, approvals, supervision every cycle; sweep, peers and revocations every 6th; housekeeping every 60th) |
| `IOT_INGEST_CONCURRENCY` | 16 | Observation batches processed concurrently; more get `429` with `Retry-After` |
| `IOT_MAX_REQUEST_BODY` | 16 MiB | Request body limit |
| `IOT_RATE_LIMIT_PER_MINUTE` | 3000 | Per-caller rate limit |
| `IOT_REQUEST_TIMEOUT_SECS` | 60 | Request timeout |
| `IOT_OBSERVATION_RETENTION_DAYS` | 14 | Raw observations (overridable per tenant: settings `retention.observation_days`) |
| `IOT_HISTORY_RETENTION_DAYS` | 400 | Change, classification and risk history, rollups, graph edges (settings `retention.history_days`) |
| `IOT_DATA_REGION` | — | Region served by this deployment (reported in status; deploy one release per region) |
| `IOT_PUBLIC_URL` | `http://localhost:8096` | Advertised URL (status) |
| `AETHER_PLATFORM_URL`, `AETHER_ISSUER`, `AETHER_AUDIENCE` | `http://localhost:8080`, platform URL, `aether` | Platform and token verification (JWKS from the platform) |
| `IOT_CLIENT_ID`, `IOT_CLIENT_SECRET` | — | Service credentials from `aether register-service` |
| `IOT_BRANCH_URL`, `IOT_PRIVATE_ACCESS_URL`, `IOT_FIREWALL_URL` | — | Peer products; unset uses the fallback |
| `IOT_VULN_FEED_URL` | — | Vulnerability feed document (bundled sample feed otherwise); refreshed daily and by `POST /api/v1/vulnerability-feed/refresh` |
| `IOT_LOG`, `IOT_LOG_JSON` | `info` | Log filter, JSON logs |

## Edge settings

| Variable | Default | Meaning |
|---|---|---|
| `IOT_PROVISIONING_KEY` | — | Platform provisioning key of a `service_edge` node group (first start only) |
| `IOT_STATE_DIR` | `/var/lib/aether-iot` | Credential (0600) and last applied configuration |
| `IOT_CONTROL_URL` | `<platform>/svc/iot` | This product's API as reached by the edge |
| `IOT_EDGE_NAME` | `iot-edge` | Node name shown in the platform |
| `IOT_SPOOL_DIR` | — | Directory of capture files (`*.pcap`, processed once stable, then deleted) |
| `IOT_TZSP_BIND` | — | UDP address for TZSP mirrored frames (e.g. `0.0.0.0:37008`) |
| `IOT_EDGE_ADMIN_BIND` | `127.0.0.1:8097` | Local API (health, metrics, status, decisions, actions) |
| `IOT_EDGE_ADMIN_TOKEN` | — | Bearer token for the local API (without it the protected routes answer 403) |
| `IOT_HEARTBEAT_SECS`, `IOT_POLL_SECS`, `IOT_FLUSH_SECS` | 30, 30, 10 | Heartbeat/status, configuration poll, observation flush |
| `IOT_EDGE_QUEUE_BATCHES` | 1000 | Observation batches kept while the control plane is unreachable (oldest dropped and counted) |
| `IOT_CONFIG_STALE_SECS` | 900 | Configuration age that raises the `policy_stale` failure mode |
| `IOT_NFT_PATH`, `IOT_EDGE_ENFORCE` | —, false | Write rendered nftables rules to this file when enforcing |
| `IOT_EDGE_ACTIVE_QUERIES` | true | Execute approved active queries |

Edge installation: run the container (`aether-iot edge`) or the binary on a
host that receives mirrored traffic (SPAN/TAP into a capture process that
writes rotated pcap files into the spool, e.g. `tcpdump -i <if> -G 10 -w
/var/spool/aether-iot/cap-%s.pcap`, or switches/APs sending TZSP). After the
first start, register a sensor for the node: `POST /api/v1/sensors
{name, site_id, kind: "edge_appliance", node_id, enforcement}`. Until then
the control plane answers `409 sensor_not_registered` and the edge keeps
its batches queued.

## Deployment

* Helm chart `deploy/helm/aether-iot-ot`: API deployment (HPA, PDB, zone
  spread), separate workers deployment, pre-install/upgrade migration job,
  service, optional ingress and network policy, optional edge DaemonSet for
  Kubernetes-based sites. Secrets come from an existing secret
  (`database-url`, `encryption-keys`, `client-id`, `client-secret`).
* Terraform example `deploy/terraform/main.tf` (secret with a generated
  data-encryption key and the Helm release).
* Container: `Dockerfile` (non-root user 10008, tini, health check).
* Platform: `aether register-service --name aether-iot-ot --product iot
  --base-url <url> --console-path /svc/iot --scopes svc.iot:nodes`.

## Monitoring

Prometheus metrics at `/metrics` (control plane `aether_iot_*`, edge
`aether_iot_edge_*`): HTTP requests and latency by route, events
(`ingest_batch`, `ingest_observation`, `log_shipped`, `decision`,
`config_apply`, `parser_panic`, `batch_dropped`, …) and state gauges
(`config_version`, `config_revision`). Alert rules:
`deploy/observability/alerts.yml`; dashboard:
`deploy/observability/dashboard.json`. `GET /api/v1/status` and
`/api/v1/diagnostics` report queues, outboxes, stage latency, platform
breaker state and peer integration health; the edge reports measured health
and active failure modes in every heartbeat and status report.

## Runbooks

### API errors
5xx above 2 %: check `/api/v1/status` (database, platform breaker), the
logs by `request_id`, the database connection count against
`IOT_DB_MAX_CONNECTIONS`. Problems carry stable `code`s; `internal_error`
is logged with the request id.

### Latency
p99 above 1 s on interactive routes: check database load (ingestion and
reports share it), scale the API deployment, move workers to their own
deployment (`config.separateWorkers`).

### Ingest backpressure
`429` on `/api/v1/node/observations`: edges keep batches queued and retry.
Raise `IOT_INGEST_CONCURRENCY` only with database headroom; otherwise
scale out. Failure mode `storage_backlog` on the edges shows the queue
fill level.

### Rejected observations
`ingest_observation{outcome="error"}`: the response of each batch lists
the rejected indexes with codes (sanitisation codes `future_timestamp`,
`stale_timestamp`, `no_address`, `multicast_mac`, `too_many_items`, or
`internal_error`). Malformed edge software versions
show up here first.

### Platform unreachable
Logs, signals and events stay in their outboxes and are retried with
back-off; approvals created later; enforcement on the edges is unaffected
(fail static). The platform client's circuit breaker state is in
`/api/v1/status`.

### Edge configuration
`config_apply{outcome="error"}`: the edge refused a manifest, artifact or
snapshot that failed verification; it keeps enforcing the previous verified
configuration and acknowledged the error to the platform (visible on the
node). Check the policy revision and the product snapshot
(`GET /api/v1/segmentation/snapshot`), then `POST /actions/resync` on the
edge.

### Parser failures
`parser_panic` on an edge: a decoder failed on a frame (contained, frame
dropped). Collect the edge diagnostics and the capture (pcap spool) and
reproduce with `aether-iot analyze`.

### Edge queue
`batch_dropped`: the edge could not ship observations for longer than its
queue holds (cloud outage or sustained backpressure). Inventory gaps for
that period are expected; enforcement is unaffected.

## Failure modes

`GET /api/v1/failure-modes` lists the 17 modes of the volume with
detection, safety impact, security impact, fallback, recovery, alert and
operator action (`iot-core/src/failure.rs`); thresholds are tunable per
tenant (settings `health_thresholds`).

## Data protection

* Collection keeps metadata only: no payloads, no credentials (SNMP
  communities and cleartext passwords are reported as findings without the
  secret), bounded strings and value lists.
* Retention: raw observations 14 days, history 400 days by default
  (tenant settings override within bounds); append-only evidence and change
  history are purged only by housekeeping.
* `POST /api/v1/privacy/erase {email}` removes a vendor principal's
  personal data.
* Secrets at rest are encrypted with the keyring; rotate by adding a key
  version (`1:…,2:…`) and redeploying.

## Backup and restore

The product database is the only state of the control plane (edges keep a
copy of their configuration). Use PostgreSQL backups (base backup + WAL);
restore, run `aether-iot migrate`, start the service; edges re-sync and
re-ship queued observations.

## Upgrades

Rolling update of the API and workers (migrations run first in the Helm
hook; they are additive). Edges are upgraded by the host package manager or
the container image; the platform's upgrade instruction from the heartbeat
is recorded in the edge status. A restarted edge enforces its persisted
configuration before reconnecting.

## Capacity

See docs/performance.md: one control-plane instance ingested 326–386
device observations per second on a shared 4 vCPU VM; an edge collects
~330 000 frames/s and decides ~125 000 flows/s per core. Size the database
for ingestion first.
