# Performance

Measured with the load driver (`crates/iot-service/tests/load.rs`):

```sh
IOT_LOAD=1 IOT_LOAD_CELLS=1200 IOT_LOAD_DECISIONS=1000000 \
IOT_TEST_DATABASE_URL=postgres://aether_iot:aether_iot@localhost:5432/aether_iot_test \
  cargo test --release -p iot-service --test load -- --nocapture
```

Environment: release build, 4 vCPU / 15 GiB development VM shared with
other services and their test suites, PostgreSQL 16 on the same VM
(default configuration, `synchronous_commit = on`), the control plane
in-process with 8 tokio worker threads. The numbers are a lower bound for a
dedicated deployment; they are the regression baseline.

## Results (2026-10-28)

| Measurement | Workload | Result |
|---|---|---|
| Passive collection (edge, one core) | 84 000 Ethernet frames of OT cells (Modbus reads/writes and identification, telnet), decode + parse + fingerprint + flow accounting | **330 687 frames/s** |
| Edge flow decisions | 1 000 000 decisions, 450 devices in the snapshot, compiled `iot.segmentation` with 50 rules, alternating read/write | **125 648 decisions/s** on one core; p50 **5.8 µs**, p99 **20.5 µs** |
| Ingestion (control plane) | 8 concurrent edges, 3 600 observations (one per device, each with signals, protocol events and flows) in batches of 60 through `POST /api/v1/node/observations` | **326 observations/s**; batch latency p50 1.42 s, p95 1.75 s, p99 1.76 s (≈ 24 ms per observation per edge); 3 600 assets created |
| Control-plane decide | 300 `POST /api/v1/segmentation/decide` with a draft rule set over HTTP | p50 **4.0 ms**, p95 8.9 ms, p99 12.2 ms |

A smaller run (300 cells, 888 observations) gave 386 observations/s and
101 747 edge decisions/s (p50 5.8 µs, p99 15.7 µs); debug builds are about
2× slower for decisions and 1.5× for ingestion.

## What dominates

* **Ingestion** is bound by PostgreSQL round trips: a full evaluation per
  observation (identity candidates, classification history, firmware,
  findings, baseline, anomalies, risk history, assignment, flow rollups and
  graph edges, typed logs, signals, change events, audit and outbox) is
  about 30–40 statements. Observations are committed in chunks of 25 with a
  savepoint per observation (one commit per chunk instead of one per
  observation: +47 % throughput), flow peers are resolved in one query per
  observation, and every identity lookup is index-backed
  (`migrations/0002_lookup_indexes.sql`).
* An observation is a device delta: the edge sends one per device that
  had traffic in the flush interval (10 s by default), so 326/s per
  instance sustains roughly 3 000 active devices per instance at the default
  interval; the control plane is stateless and scales out (Helm HPA),
  ingestion is bounded by `IOT_INGEST_CONCURRENCY` (429 beyond, with edges
  keeping batches queued) and the database is the shared limit.
* **Edge decisions** evaluate the prepared policy (indexed rule matching)
  after the exception scan; the runtime is swapped atomically, so
  decisions never wait on configuration updates.
* **Collection** is a single pass over each frame with bounded parsers;
  per-device state is bounded (`Limits`), so memory stays flat under
  scans and floods (tested by `gateway_macs_are_not_identities_and_limits_hold`).

## Budgets used by the tests

The CI job runs the load driver with small sizes as a smoke test; the
release numbers above are the reference for capacity planning
(docs/operations.md, "Capacity").
