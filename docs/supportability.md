# Supportability

## What this is

When a probectl deployment misbehaves, you want to hand a diagnostician a single
file that says what's wrong — without that file leaking any secrets. That's what
this layer provides:

- a one-command **support bundle** (triage-grade diagnostics, packaged — a
  flight data recorder for the deployment: it captures the instruments, never
  the passengers' conversations),
- **deep health checks** (per-component status, plus one "is it healthy?" answer),
- **actionable readiness findings** (a stable local task for every unhealthy
  component, with bounded redacted evidence and a safe in-product next step),
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
| `GET /v1/diagnostics` | the live native diagnostics contract: deep health, deployment-local process metrics, and build identity. Admin-only — requires `diagnostics.read`; it contains no tenant telemetry. |
| `probectl diagnostics status` | the same live JSON diagnostics contract, including self-metrics and build identity, for local scripts and terminals. |
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
| `alert_evaluator` | stored alert rules are not being evaluated → `degraded` |
| `secrets_resolver` | a configured secret backend is failing → `degraded` |
| `cluster` | writes are fenced during a multi-region failover → `degraded` |
| `license` | expired into the grace period or read-only state → `degraded` |

Every `degraded` or `down` check carries one `finding`; an `ok` check never
fabricates a task. A finding contains:

| Field | Meaning |
|---|---|
| `id` | stable machine key such as `readiness.cluster` |
| `component`, `scope` | the affected component and the redacted `deployment` scope |
| `severity` | `warning` for degraded, `critical` for down |
| `observed_at` | exactly the report's local `checked_at` time |
| `summary`, `evidence` | bounded operator text; raw dependency errors and secret values are never copied |
| `next_action` | a relative local `navigate` or `download` link; it never runs remediation |

The native Admin → Support & diagnostics card shows the local process snapshot
and build identity alongside findings and the underlying component table. The
same contract is available to the CLI and generated Go/TypeScript SDKs. During
a rolling upgrade an older replica may omit self-metrics, build identity, or
finding details. Each missing section is displayed as unavailable/incomplete;
the UI does not invent a value or pretend that state is healthy.

This is separate from the liveness/readiness probes (`/healthz`, `/readyz`) —
**liveness** asks "is the process alive at all?" and **readiness** asks "should
the load balancer send it traffic right now?". Those answer a blunt up/down for
machines making routing decisions. The deep report is richer — it's for a human
doing **triage** (deciding what is broken and what to look at first) and for
the support bundle.

The endpoint is a tenant-authenticated, `diagnostics.read`-authorized sensitive
read and is audited by the central route policy. Its current findings are
deployment-wide and redacted: no tenant identifier, hostname, IP address,
credential, or telemetry is returned. There is no remote advisor, cloud model,
plugin catalog, phone-home, or outbound request in this path. If a future check
uses tenant data, it must resolve tenant scope at the storage layer before
RBAC, with a cross-tenant isolation test.

## Self-monitoring (probectl observes probectl)

The control plane collects and emits `probectl_self_*` metrics every 30 seconds —
`goroutines`, `mem_alloc_bytes`, `mem_sys_bytes`, `num_gc`, `uptime_seconds`,
`max_procs` — plus `probectl_build_info{version,commit,go}` (value `1`, the
standard Prometheus build-info trick: the *labels* carry the info, the value is
just a constant). The authoritative, dependency-free native view is
**Admin → Support & diagnostics**, backed by `GET /v1/diagnostics`; it shows
goroutines, memory, garbage collections, uptime, process capacity, and build
identity. It is intentionally administrator-only because these are
deployment-global process facts. The response contains no tenant identity,
labels, or telemetry. Agent scrape targets add tenant-agnostic
`probectl_agent_*` RED/USE
series: collection and publish rates, errors, bounded-buffer depth, and latest
publish latency.

The product does not bundle or require an external dashboard runtime. The
`/metrics` output and any example dashboard JSON are optional,
operator-supplied protocol interoperability only; they are not the
authoritative probectl surface, a runtime dependency, or part of the shipped
application path.

## Configuration

No new config keys. The diagnostics endpoints and the offline CLI read the
existing config. The `diagnostics.read` permission that gates the endpoints is
seeded for admins by migration `0034_diagnostics.sql`.

## Completeness gate

The bundle's section set is pinned by a CI test
(`internal/support/completeness_test.go`, EXC-ORG-03): version, redacted config,
health, self-metrics, topology summary, runtime, and the manifest. Dropping a
section — the bundle silently shrinking so it no longer carries what an F500
support contract needs to triage — reds the build, as does the manifest index
drifting from the actual contents or a secret slipping through (the companion
`TestBundleHasNoSecrets`).

## Out of scope

The support **organization and SLAs** (the Enterprise/acquirer-provided
contract — not code). In MSP mode, tier-1 support to end customers is the MSP's
job. The **DR drill on real multi-region infrastructure** is likewise an operator
action: the runbook + the CI failover drill exist (`docs/ops/dr.md`), but the
live cross-region exercise needs real DR infra and is run by the operator, not in
CI.
