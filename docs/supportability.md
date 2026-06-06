# Supportability (S-EE4, F35)

probectl is built to be diagnosable: a one-command **support bundle** captures
triage-grade diagnostics, **deep health checks** report per-component status,
and **self-monitoring** series let probectl observe itself. These are **core**
by the ratified editions decision — better bug reports serve every deployment.
The support *org / SLA* is a commercial contract (the Enterprise entitlement),
not code.

**The non-negotiable property (guardrail 6): a support bundle never contains
secrets, credentials, or PII.**

---

## Support bundle

A `tar.gz` of JSON diagnostics:

| File | Contents |
|---|---|
| `manifest.json` | format version, generated-at, probectl version, file list |
| `version.json` | build version / commit / Go version / OS / arch |
| `config-redacted.json` | operational config — **allowlist** (no secrets) |
| `health.json` | the deep-health report (per component + aggregate) |
| `self-metrics.json` | goroutines, memory, uptime, GC, GOMAXPROCS |
| `topology-summary.json` | **anonymized** counts (tenants, agents, isolation models, region) — no tenant identifiers or telemetry |
| `runtime.json` | runtime snapshot |

### How it stays secret-free (defense in depth)

1. **Allowlist config.** `config.Redacted()` only includes known-non-secret
   operational keys; DSNs are password-redacted; the envelope key appears only
   as the boolean `envelope_key_configured`. A new secret field added later
   cannot leak because it is simply not on the list.
2. **Anonymized topology.** Counts only — never a tenant ID, hostname, IP, or
   any telemetry.
3. **A final scrub.** The bundle is additionally scrubbed of the deployment's
   known sensitive values (envelope key, OIDC/CMDB/SIEM/AI secrets,
   bootstrap/OTLP tokens, the DSN password) — so even an accidental inclusion
   is replaced with `***REDACTED***`. The test asserts these values never
   appear anywhere in the bundle bytes.

Each file is bounded (4 MiB) and the whole bundle is gzip'd.

### Getting a bundle

| Method | Use |
|---|---|
| `GET /v1/diagnostics/bundle` | the live bundle (topology, deep health, self-metrics) — admin `diagnostics.read`; Admin → Support & diagnostics has the download button |
| `probectl-control support-bundle [-o file]` | an **offline** bundle from this install (version, redacted config, a DB health check, runtime) — no running server needed |

## Deep health checks

`GET /v1/diagnostics` (admin `diagnostics.read`) returns each component's
status — `ok` / `degraded` / `down` — and an **aggregate that is the worst
component**, so a single field tells you whether the deployment is healthy:

| Check | Degraded / down when |
|---|---|
| `database` | the writer pool ping fails (down) |
| `secrets_resolver` | a secret backend is failing (degraded) |
| `cluster` | writes are fenced during a failover (degraded, S-EE2) |
| `license` | expired into grace / read-only (degraded, S-T0) |

This is distinct from the liveness/readiness probes (`/healthz`, `/readyz`):
those gate load-balancer traffic; the deep report is for human triage and the
support bundle.

## Self-monitoring (probectl observes probectl)

The control plane emits `probectl_self_*` series every 30s — `goroutines`,
`mem_alloc_bytes`, `mem_sys_bytes`, `num_gc`, `uptime_seconds`, `max_procs` —
plus `probectl_build_info{version,commit,go}` (value 1, the Prometheus
build-info idiom). With the S-EE2 `probectl_cluster_*` and S-T7
`probectl_fairness_*` series, these feed a self-monitoring dashboard:

```
deploy/grafana/dashboards/probectl-self.json
```

Import it into Grafana (or drop it into a provisioned dashboards folder). It
shows build/uptime/goroutines/memory, the cluster writer role + replica lag per
region, and per-tenant fairness shedding + query rejections.

## Configuration

No new config keys. The diagnostics endpoints and the offline CLI read the
existing config; `diagnostics.read` (migration 0034, admin-seeded) gates the
endpoints.

## Out of scope

The support **organization / SLAs** (Enterprise/acquirer-provided — contract,
not code). In MSP mode, tier-1 support to end customers is the MSP's job.
