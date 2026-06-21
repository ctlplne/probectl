# Runbook: probectl Self-Alerts

## What This Is

These alerts watch probectl itself: scrape presence, process pressure, and
cluster writer posture. They use only process-level or aggregate metrics
(`probectl_self_*`, `probectl_build_info`, `probectl_cluster_*`). They do not
carry tenant telemetry and they never trigger remediation automatically.

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

## Tuning

The Helm defaults live under `metrics.prometheusRule.thresholds`. Keep
thresholds conservative until local baseline dashboards show normal process
shape for your tenant count, ingest rate, and retention settings.
