# Supportability

## What this is

When a probectl deployment misbehaves, you want to hand a diagnostician a single
file that says what's wrong — without that file leaking any secrets. That's what
this layer provides:

- a one-command **support bundle** (triage-grade diagnostics, packaged — a
  flight data recorder for the deployment: it captures the instruments, never
  the passengers' conversations),
- **deep health checks** (per-component status, plus one "is it healthy?" answer),
- **self-monitoring** (probectl emits metrics *about itself* — the monitoring
  platform is also a service someone has to operate).

All three are **core** (free, every deployment gets them) — better bug reports
help everyone. The paid part is the support *organization and SLA* (the
Enterprise entitlement); that's a contract, not code.

**The non-negotiable property: a support bundle never contains secrets,
credentials, or PII** (it falls under the project's secrets-handling
[non-negotiables](../CONTRIBUTING.md#non-negotiables)). Everything below is
built to keep that true even if someone slips up.

---

## Support bundle

A `.tar.gz` of JSON files. The code lives in `internal/support/bundle.go`.

| File | Contents |
|---|---|
| `manifest.json` | format version, when it was generated, probectl version, the file list |
| `version.json` | build version / commit / Go version / OS / arch |
| `config-redacted.json` | operational config — an **allowlist** (no secrets) |
| `health.json` | the deep-health report (each component + the aggregate) |
| `self-metrics.json` | goroutines, memory, uptime, GC, GOMAXPROCS |
| `topology-summary.json` | **anonymized** counts (tenants, agents, isolation models, region) — no tenant identifiers, no telemetry |
| `runtime.json` | a runtime snapshot of the process |

### How it stays secret-free (defense in depth)

Three independent layers, so no single mistake leaks a secret:

1. **Allowlist config, not blocklist.** An **allowlist** names what may enter —
   a guest list; a **blocklist** names what may not — a bouncer's memory of past
   troublemakers, which fails precisely when a *stranger* walks up. Secrets
   added in next year's release are strangers. So `config.Redacted()` builds the
   config snapshot from a fixed list of *known-non-secret* keys. Database URLs
   have their passwords stripped; the envelope encryption key shows up only as
   the boolean `envelope_key_configured` (true/false), never the key itself. The
   safety is structural: a secret field someone adds *later* can't leak,
   because it simply isn't on the allowlist.
2. **Anonymized topology.** The deployment-shape file is counts only — never a
   tenant ID, hostname, IP, or any telemetry.
3. **A final scrub.** Before the bundle is written, it's swept once more for the
   *specific* sensitive values this deployment actually holds — the envelope
   key, the OIDC / CMDB / SIEM / AI-model secrets, the provider-bootstrap and
   OTLP tokens, and the database password. Any of those found anywhere in the
   bundle bytes is replaced with `***REDACTED***`. A test asserts these values
   never appear in the output. So even an accidental inclusion is caught.

Each file is bounded (4 MiB max) and the whole bundle is gzip'd.

### Getting a bundle

| Method | Use |
|---|---|
| `GET /v1/diagnostics/bundle` | the **live** bundle (topology, deep health, self-metrics). Admin-only — requires the `diagnostics.read` permission. The Admin → Support & diagnostics page has the download button. |
| `probectl-control support-bundle [-o file]` | an **offline** bundle straight from the binary (version, redacted config, a database health check, runtime) — no running server needed. |

## Deep health checks

`GET /v1/diagnostics` (admin `diagnostics.read`) returns each component's status
— `ok` / `degraded` / `down` — plus an **aggregate that equals the worst
component**, so one field tells you whether the deployment is healthy. Worst,
not average, because a deployment is only as healthy as its sickest dependency
— one amber bulb makes the whole panel amber. The
checks are wired up in `internal/control/diagnostics.go`:

| Check | Degraded / down when |
|---|---|
| `database` | the writer connection-pool ping fails → `down` |
| `secrets_resolver` | a configured secret backend is failing → `degraded` |
| `cluster` | writes are fenced during a multi-region failover → `degraded` |
| `license` | expired into the grace period or read-only state → `degraded` |

This is separate from the liveness/readiness probes (`/healthz`, `/readyz`) —
**liveness** asks "is the process alive at all?" and **readiness** asks "should
the load balancer send it traffic right now?". Those answer a blunt up/down for
machines making routing decisions. The deep report is richer — it's for a human
doing **triage** (deciding what is broken and what to look at first) and for
the support bundle.

## Self-monitoring (probectl observes probectl)

The control plane emits `probectl_self_*` metrics every 30 seconds —
`goroutines`, `mem_alloc_bytes`, `mem_sys_bytes`, `num_gc`, `uptime_seconds`,
`max_procs` — plus `probectl_build_info{version,commit,go}` (value `1`, the
standard Prometheus build-info trick: the *labels* carry the info, the value is
just a constant). Together with the multi-region `probectl_cluster_*` series and
the per-tenant fairness `probectl_fairness_*` series, these feed a ready-made
dashboard:

```text
deploy/grafana/dashboards/probectl-self.json
```

Import it into Grafana (or drop it into a provisioned dashboards folder). It
shows build/uptime/goroutines/memory, the cluster writer role and per-region
replica lag, and per-tenant fairness shedding plus query rejections.

## Configuration

No new config keys. The diagnostics endpoints and the offline CLI read the
existing config. The `diagnostics.read` permission that gates the endpoints is
seeded for admins by migration `0034_diagnostics.sql`.

## Out of scope

The support **organization and SLAs** (the Enterprise/acquirer-provided
contract — not code). In MSP mode, tier-1 support to end customers is the MSP's
job.
