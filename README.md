# Aether IoT/OT Security

Aether IoT/OT Security (product code `IOT`, platform product key `iot`,
permission domain `policy.iot`) protects unmanaged, IoT and operational
technology devices. Edge appliances passively observe mirrored traffic
and identify every device from flow, DHCP, DNS, HTTP user-agent, mDNS/SSDP,
LLDP/CDP, TLS and industrial-protocol metadata; a deterministic,
explainable classifier assigns type, vendor, model, OS and firmware with a
confidence; the inventory carries risk, vulnerabilities and anomalies; OT
protocols are parsed with every operation classified as read, write,
control, program or firmware; segmentation policies over device groups and
zones are learned from baselines, simulated, rolled out in stages and
enforced on the edge; and vendors get just-in-time, approved, recorded
remote access to OT assets. It is an Aether product service: tenants,
identities, the console, the policy workflow, approvals, node enrolment and
the log store are provided by the Aether platform.

## Capabilities

| Area | What it does | Main APIs |
|---|---|---|
| Passive discovery | Edge collector (pcap spool, TZSP mirror), Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP decoding, DHCP options and parameter lists, DNS/mDNS, HTTP and SSDP, LLDP/CDP, TLS client-hello fingerprints, TCP SYN hints, flow summaries; gateway MACs never become identities; bounded memory | `aether-iot edge`, `POST /api/v1/node/observations` |
| OT protocol awareness | Modbus/TCP, DNP3, BACnet/IP, S7comm, EtherNet/IP (CIP), OPC UA, PROFINET (DCP/RPC), IEC 60870-5-104, MQTT, AMQP, SNMP parsers; port and signature identification; operation classes `session < read < diagnostic < write < control < program < firmware`; device identity from protocol answers; fuzz-tested | `/api/v1/protocols` |
| Classification | 200+ built-in rules over OUI, DHCP, DNS, HTTP, mDNS, LLDP/CDP, TLS, services, protocol roles and identities, behaviour; noisy-OR confidence per dimension, tiers, conflicts; tenant rules and learned TLS/DHCP rules; overrides with reason; full explanation | `/api/v1/assets/{id}/classification`, `/override`, `/api/v1/classification-rules` |
| Inventory | Multi-key identity (MAC, serial, hostname, client id, TLS, never IP alone), randomised-MAC handling, merge and split, lifecycle (discovered → active → inactive → decommissioned), business context, search, saved views, assertions, CSV/JSON export and import, timeline | `/api/v1/assets`, `/api/v1/inventory/summary`, `/api/v1/search` |
| Risk and exposure | Explainable risk (vulnerability, exposure, behaviour, protocol, identity confidence, threat intelligence, end of life) with tenant tuning, operational impact and priority; firmware/CVE mapping behind a `VulnFeed` trait with an offline sample feed; default-credential, cleartext-credential and insecure-protocol findings | `/api/v1/assets/{id}/risk`, `/api/v1/findings`, `/api/v1/vulnerability-feed` |
| Baselines and anomalies | Network and process learning with automatic completion, allow-lists, drift (new peers, ports, protocols, operations, internet destinations, value ranges), signatures (controller mode changes, program downloads, scans, unauthorised engineering stations, malformed bursts), threat-indicator matches; snapshots and differences; alerts | `/api/v1/assets/{id}/baseline`, `/api/v1/anomalies`, `/api/v1/alerts` |
| Segmentation | Zones (IEC 62443 security levels, observe/simulate/enforce), device groups with dynamic assignment (privileged groups only for confident identities), `iot.segmentation` policy type and `iot.*` operands on `firewall.network`, recommendations from baselines, simulation over observed flows, temporary exceptions with approval, staged rollouts, configuration revisions and rollback, conduits | `/api/v1/segmentation/*`, `/api/v1/exceptions`, `/api/v1/rollouts`, `/api/v1/config-revisions` |
| Edge appliance | Enrols as a platform node (`service_edge`), verified manifests and artifacts, hashed product snapshot, fail-static restart, local decision API, nftables rendering, bounded observation queue, safe active queries, health and failure modes | `aether-iot edge`, `POST /v1/decide` (local) |
| Privileged remote access | Vendor principals, remote targets, just-in-time windows, `iot.remote_access` policy, platform approval inbox with separation of duties, sessions brokered by Aether Private Access (credentials stay vaulted), supervision (window end, max duration, idle, revocation), termination, recording metadata | `/api/v1/access-requests`, `/api/v1/remote-sessions` |
| Operations | Typed `iot_*` logs, risk signals (`subject_type` workload), events, dashboards and wizards for the console, reports, investigations with hashed evidence, acceptance runs, failure-mode catalogue, diagnostics, retention and privacy erasure | `/api/v1/dashboards/*`, `/api/v1/reports/*`, `/api/v1/acceptance/runs` |

Platform integration: registers the `iot.segmentation`, `iot.remote_access`
and `iot.active_query` policy types, the `iot.*` extension of
`firewall.network`, action owners, seven `iot_*` log schemas and the policy
reference / simulation hooks; reads active revisions; creates and mirrors
approvals; ships logs and risk signals; relays its outbox and audit trail;
honours the revocation feed. Peer products (Aether Branch inventory,
Aether Private Access privileged consoles and sessions, Aether Firewall
identity bindings) are reached over HTTP behind traits with fallbacks.

## Layout

```
crates/iot-core     engines without I/O: packet decoding, protocol parsers,
                    fingerprints, collector, classifier, taxonomy, identity,
                    risk, vulnerability feed, baselines, graph, segmentation,
                    policy types, remote access, active queries, assertions,
                    failure modes, acceptance harness, capability catalogue
crates/iot-service  control plane (API, pipeline, workers, platform client,
                    integrations) and the edge appliance; binary `aether-iot`
migrations/         PostgreSQL schema (row-level security on every table)
scripts/            requirement extraction and coverage report
docs/               architecture, API, operations, performance, traceability,
                    platform gaps, requirements
deploy/             Helm chart (API, workers, migrations, optional edge
                    DaemonSet), Terraform example, alert rules and dashboard
```

## Running

```sh
export IOT_DATABASE_URL=postgres://aether_iot:aether_iot@localhost:5432/aether_iot   # NOSUPERUSER NOBYPASSRLS role
export IOT_ENCRYPTION_KEYS="1:$(openssl rand -base64 32)"
export AETHER_PLATFORM_URL=http://127.0.0.1:8080 AETHER_ISSUER=http://localhost:8080
# Register with the platform (prints the client id and secret once):
aether register-service --name aether-iot-ot --product iot --base-url http://127.0.0.1:8096 --console-path /svc/iot --scopes svc.iot:nodes
export IOT_CLIENT_ID=... IOT_CLIENT_SECRET=...
cargo run -p iot-service --bin aether-iot -- serve       # API and workers on :8096

# Edge appliance (provisioning key of a service_edge node group):
IOT_PROVISIONING_KEY=... IOT_SPOOL_DIR=/var/spool/aether-iot IOT_TZSP_BIND=0.0.0.0:37008 \
  IOT_EDGE_ADMIN_TOKEN=... cargo run -p iot-service --bin aether-iot -- edge
# Register a sensor bound to the enrolled node: POST /api/v1/sensors {"node_id": ...}

# Offline analysis of a capture file:
cargo run -p iot-service --bin aether-iot -- analyze capture.pcap
```

See [docs/operations.md](docs/operations.md) for every setting.

## Tests

```sh
cargo test                                                                                  # unit tests
IOT_TEST_DATABASE_URL=postgres://aether_iot:aether_iot@localhost:5432/aether_iot_test cargo test   # + API, edge, governance tests
IOT_E2E=1 AETHER_BIN=/path/to/aether cargo test -p iot-service --test e2e -- --nocapture         # live platform
IOT_LOAD=1 IOT_TEST_DATABASE_URL=... cargo test --release -p iot-service --test load -- --nocapture  # load driver
```

API tests run the service in-process against PostgreSQL with locally
signed platform tokens and in-process fakes of the peer products; traffic
is synthesised as Ethernet frames and passed through the real collector.
Edge tests run the appliance against a mock platform (enrolment, tokens,
signed manifests) and the real control plane. The end-to-end test runs
against a live platform.

## Requirements

`docs/requirements/` holds the extracted requirement inventory (15,448 ids
of the IoT/OT volume and 100 of the platform volume's IOT module), 36
authored requirements from the parity research (`added.md`), the mapping
rules and the generated coverage (`coverage.tsv`, `coverage.md`):

```sh
python3 scripts/extract_requirements.py --v11 <IoT/OT volume>.txt --p2 <platform volume 2>.txt --v3 <UI volume>.txt
python3 scripts/coverage_report.py --check
```

[docs/traceability.md](docs/traceability.md) maps capabilities to code and
tests; [docs/platform-gaps.md](docs/platform-gaps.md) lists what the platform
does not provide yet.
