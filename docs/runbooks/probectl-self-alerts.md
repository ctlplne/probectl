# Runbook: probectl Self-Alerts

## What This Is

These alerts watch probectl itself: scrape presence, process pressure, and
cluster writer posture, plus aggregate operational safety signals for ingest,
the bus, ClickHouse-backed stores, the agent registry, fairness, and audit WORM
export. They use only process-level or aggregate metrics (`probectl_self_*`,
`probectl_build_info`, `probectl_cluster_*`, `probectl_bus_*`,
`probectl_agent_registry_*`, `probectl_audit_worm_*`, and summed
`probectl_fairness_*`). They do not carry tenant telemetry and they never trigger
remediation automatically.

## First Checks

1. Confirm the control plane is reachable:

   ```sh
   curl -fsS https://<probectl-host>/healthz
   curl -fsS https://<probectl-host>/readyz
   ```

2. Confirm Prometheus can scrape `/metrics` through the rendered
   `ServiceMonitor` and the NetworkPolicy allows the monitoring namespace.

3. Check recent deploys, config changes, and dependency outages before raising a
   tenant-facing incident.

## Alerts

| Alert | Meaning | First response |
| --- | --- | --- |
| `ProbectlSelfMetricsMissing` | Prometheus has not seen `probectl_build_info` during the configured window. | Check the control-plane pod/process, `/metrics`, ServiceMonitor labels, and scrape TLS settings. |
| `ProbectlHighGoroutines` | Goroutines are above the configured threshold for long enough to avoid one-off spikes. | Inspect goroutine profiles, stuck outbound integrations, and recent ingest/query load. |
| `ProbectlHighMemory` | Process memory is above the configured threshold. | Inspect heap profiles, large query bursts, and backlog growth. |
| `ProbectlWritesPaused` | Cluster fencing reports writes are paused. Reads may still work. | Follow [region-failover.md](region-failover.md); verify writer endpoint, promotion epoch, and database reachability. |
| `ProbectlReplicaLagHigh` | Postgres replica lag is above the configured threshold. | Check replication health before failover; lag widens metadata RPO for asynchronous replicas. |
| `ProbectlDLQGrowth` | Ingest or OTLP dead-letter counters increased. | Stop the source error first, then follow [dead-letter-replay.md](../ops/dead-letter-replay.md) so replay is deliberate and tenant-scoped. |
| `ProbectlBusShedOrHandlerErrors` | The result bus is shedding records, losing in-memory records, or handlers are erroring. | Follow [data-plane.md](../ops/data-plane.md); treat this as at-least-once delivery pressure until producers retry cleanly. |
| `ProbectlClickHouseWriteOrBreakerFailures` | ClickHouse insert errors increased or a ClickHouse circuit breaker opened/short-circuited. | Verify ClickHouse health, migrations, retention pressure, and per-silo routing before declaring telemetry complete. |
| `ProbectlAgentDarkFleet` | Too much of the aggregate registered fleet has stale heartbeats. | Follow [fleet-rollout.md](../ops/fleet-rollout.md); check control-plane reachability, recent rollouts, and registry heartbeat freshness. |
| `ProbectlFairnessShedOrRejected` | Fairness shed units or rejected queries increased. | Confirm noisy-tenant pressure and quiet-tenant health; tune limits only after proving the gate protected the shared platform. |
| `ProbectlWORMExportGap` | The WORM exporter has not completed a successful export+verify cycle recently. | Verify object-store reachability, signing key persistence, and provider audit stream health before pruning any audit history. |
| `ProbectlWORMSignatureFailures` | Signed WORM segments failed signature or hash-chain verification. | Treat as possible tampering, missing objects, or wrong signing key; preserve the bucket and verify with the persisted public key. |
| `ProbectlTenantQuarantined` | A replica holds a siloed or hybrid tenant quarantined (D-62): an isolation precondition failed, so every read and write of that tenant is refused while every other tenant runs. | Open the provider console's quarantined-tenants list (or `GET /provider/v1/tenants/quarantine`) for the tenant, the cause and the fix; apply the fix; the replica releases the tenant itself. |

### ProbectlSelfMetricsMissing

Prometheus cannot see the control plane's own `probectl_build_info`. Check the
pod/process, ServiceMonitor selector, scrape TLS settings, and NetworkPolicy
path before trusting any other probectl dashboard.

### ProbectlHighGoroutines

The process has too many goroutines for the configured window. Pull a goroutine
profile, then look for stuck outbound integrations, long ingest drains, or query
fan-out that is not returning.

### ProbectlHighMemory

The control-plane process is above its memory threshold. Check heap profiles,
large query bursts, unbounded backlog growth, and recent changes that increased
cardinality.

### ProbectlWritesPaused

The HA fence says writes are not usable. Reads may still answer, but mutable
workflows must stay paused until the writer endpoint and promotion epoch are
healthy. Continue in [region-failover.md](region-failover.md).

### ProbectlReplicaLagHigh

Postgres replica lag is too high. Do not perform an asynchronous failover until
you understand the lag, because the lag becomes metadata RPO.

### ProbectlDLQGrowth

Dead-letter growth means a pipeline could not safely store or normalize a
payload. First fix the source error, then replay through
[dead-letter-replay.md](../ops/dead-letter-replay.md); never bulk-replay across tenants
or without checking the original tenant scope.

### ProbectlBusShedOrHandlerErrors

The bus is reporting shed records, in-memory drops, lost handler retries, or
handler errors. This is the middle of the ingest pipe, so follow
[data-plane.md](../ops/data-plane.md): confirm producers retry, consumers are
running, and no broker/backpressure setting is silently discarding data.

### ProbectlClickHouseWriteOrBreakerFailures

ClickHouse write errors or breaker trips mean high-cardinality telemetry may be
missing even if the API is up. Check ClickHouse reachability, disk/parts pressure,
schema migration state, per-silo routing, and whether the breaker is still open.

### ProbectlAgentDarkFleet

The aggregate registry shows too many stale agent heartbeats. Treat it as a
coverage outage: follow [fleet-rollout.md](../ops/fleet-rollout.md), confirm the
last rollout did not strand a cohort, and check that agents can still reach the
mTLS listener.

### ProbectlFairnessShedOrRejected

Fairness shedding is a pressure valve, not a bug by itself. Confirm whether one
tenant or workload is noisy, verify quiet tenants still receive capacity, then
tune the configured limits only if the current limits are too low for the
deployment size.

### ProbectlWORMExportGap

The provider audit WORM exporter has not completed a successful export+verify
cycle recently. Check object-store reachability, bucket retention/object-lock
posture, `PROBECTL_AUDIT_WORM_INTERVAL`, and persisted signing-key access before
pruning any in-database audit rows. `probectl_audit_worm_lagging=1` means the
last cycle exported its bounded eight-page allowance but a read-only probe found
more provider events; `probectl_audit_worm_lagged_cycles_total` counts those
cycles. Do not mistake successfully written partial catch-up for a fully current
off-database trail—the last-success timestamp intentionally remains unchanged.

### ProbectlWORMSignatureFailures

WORM signature or hash-chain verification failed. Preserve the object-store
contents, verify the persisted public key under `worm/audit/provider/signing.pub`,
and treat missing/corrupt segments as audit-integrity incidents until explained.

### ProbectlTenantQuarantined

With `PROBECTL_SILO_FAILURE_MODE=quarantine` (D-62), a replica that cannot prove
a siloed or hybrid tenant's isolation targets at startup quarantines that
tenant instead of refusing to start: the tenant's users get HTTP 503
`tenant_quarantined`, its bus lanes wait unconsumed, its erasure is refused,
and every other tenant runs normally. The `reason` label names the failed
precondition:

| reason | cause | fix |
| --- | --- | --- |
| `residency_plane_missing` | The tenant's residency plane is not in `PROBECTL_DATAPLANES` (DPR-324). | Restore the plane (and its credential entries) and roll the control plane, or move the tenant. |
| `residency_plane_unreachable` | The plane's ClickHouse could not be reached to prove the reader scope. | Restore connectivity (DNS, TLS trust, firewall, server health); released automatically, no restart. |
| `reader_credential_missing` | The reader login has no credential for the plane (DPR-327). | Add the plane to `PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES` and roll the control plane. |
| `reader_scope_unproven` | The plane answered but the reader row policy/grants could not be installed or proven (DPR-323/326/328). | Grant the control login `SELECT ON *.* WITH GRANT OPTION`; keep the reader SQL-created and SELECT-only; released automatically. |
| `silo_schema_catchup_failed` | The siloed tenant's Postgres schema could not be caught up (ARCH-001). | Fix the named precondition (usually the migration login); released automatically. |

The provider console's quarantined-tenants list (`GET
/provider/v1/tenants/quarantine`) shows each tenant, replica, cause and fix.
The supervisor re-checks every `PROBECTL_SILO_QUARANTINE_RECHECK_INTERVAL`;
entering and leaving quarantine is audited on the tenant's chain and the
provider stream (`tenant.quarantine_entered` / `tenant.quarantine_released`).
A cause that is configuration clears when the corrected configuration is rolled
out. While the tenant's lanes wait, Kafka keeps their committed offsets for
the broker's `offsets.retention.minutes` (7 days by default); fix a quarantine
well inside that window.

## eBPF agent alerts (probectl-agent chart)

The agent chart ships its own opt-in pack (`metrics.prometheusRule.enabled`,
which requires `metrics.enabled`) for the eBPF agent's process metrics. It
carries no tenant telemetry.

### ProbectlEBPFChannelCertExpiring

An eBPF agent's control-plane policy-channel certificate has less than
`metrics.prometheusRule.channelCertExpirySeconds` (default 6 h) left. The agent
renews it at two thirds of its lifetime (16 h of 24 h), so renewals have been
failing for hours. Check the agent log for `certificate rotation FAILED` and
`probectl_ebpf_control_plane_cert_rotation_failures_total`. Typical causes are
the control plane's API (`controlPlane.apiURL`) being unreachable or not
chaining to `server-ca.pem`, a revoked identity, or a read-only identity
directory. Once the certificate has expired, consented L7 capture is refused
(`probectl_ebpf_l7_capture_channel_refused` = 1) while flows continue. An
expired identity cannot rotate itself; re-register the collector
(`POST /v1/collectors/register`, `plane=ebpf`) and update the identity Secret.

## Tuning

The Helm defaults live under `metrics.prometheusRule.thresholds`. Keep
thresholds conservative until local baseline dashboards show normal process
shape for your tenant count, ingest rate, and retention settings.
