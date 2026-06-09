# Tenant fairness / noisy-neighbor isolation

## What this is

In a pooled deployment many tenants share the same pipeline, the same stores,
and the same query engine. The danger is the **noisy neighbor**: one tenant
dumping a firehose of results, or hammering the query API, slowing everyone
else down. This layer stops that — it bounds each tenant's use of the shared
platform with **per-tenant fairness policies**: ingest rate limits, query-cost
guards, and full accounting so nothing is silent.

Where it lives matters. Enforcement is in **core** (`internal/fairness`), in
*every* edition — because protecting the shared platform is the platform's own
job, not a paid add-on. Only the cross-tenant operator *views* and the *tuning*
surface ride the commercial provider plane (`ee/`, the `provider_plane`
feature). A single-tenant deployment has no neighbors to be noisy, so it simply
never trips anything.

## The three mechanisms

**Ingest rate bounds.** A token bucket per `(tenant, meter)` wraps the result
and flow consumers. The admission check happens **before** the expensive work
(decode → enrich → write to the store), so an over-rate tenant's burst is shed
in O(1) and never stalls the shared pipeline — the cost of saying "no" is tiny.
Because the gate wraps the *consumer* (not the bus), it behaves identically
whether the bus is Kafka or one of the lightweight modes. The meters share the
metering vocabulary — `results_ingested`, `flow_events`, `ingest_bytes`, and
`device_metrics` (the SNMP/gNMI device plane) — so metering, quotas, and
fairness all agree on what one "unit" is. Shed messages are **not** counted for
billing (billing reflects stored work); fairness accounting records the shed
separately.

**Query-cost guards.** Two limits per tenant on the expensive query surfaces:
how many queries it may have **in flight at once** (concurrency), and how many
it may run **per minute** (a budget). This extends the deployment-wide row and
timeout guards with a per-*tenant* dimension. The guarded surfaces are
`/v1/ai/ask`, the Grafana-compatible PromQL proxy (`query` / `query_range`), and
the MCP events tool. A rejection is **`429 rate_limited` with a `Retry-After`
header** — an over-budget tenant gets a clear, immediate signal instead of a
slow platform for everyone.

**Accounting.** Per-tenant admitted / shed / rejected counters surface in three
places: `GET /v1/fairness` (the tenant's own view — debugging a fairness dispute
never requires the provider's word), the provider console's Fairness card (a
commercial surface), and as TSDB series (Grafana-federable; written every 30
seconds).

## The policy model

A policy is a set of bounds. Two of the bounds default to "unlimited", and the
rest default to **sane, generous limits** — see the table for which is which.

| Field | Meaning |
|---|---|
| `results_per_sec` | result messages admitted per second |
| `flow_events_per_sec` | flow records admitted per second |
| `ingest_bytes_per_sec` | result payload bytes admitted per second |
| `device_metrics_per_sec` | device (SNMP/gNMI) samples admitted per second |
| `burst_seconds` | bucket capacity = rate × burst (default 10) |
| `query_concurrency` | max in-flight queries (0 = unlimited) |
| `queries_per_min` | per-minute query budget; 0 = unlimited (the bucket holds one full minute) |
| `weight` | operator vocabulary for relative share (recorded, not yet used to gate) |

**Defaults are bounded for ingest, unlimited for queries.** The deployment ships
with real ingest ceilings out of the box (see the configuration table below for
the exact numbers): generous enough for real fleets, a hard wall for a runaway
tenant. The two query guards default to 0, meaning unlimited. This is a
deliberate posture — the shared *ingest* pipeline is the most likely thing one
tenant can wreck, so it is protected by default.

**How values resolve.** Deployment-wide defaults come from the
`PROBECTL_FAIRNESS_*` keys. Per-tenant overrides live in the `tenant_fairness`
table (migration `0031_fairness.sql`) and are set from the provider console
(`PUT /provider/v1/tenants/{id}/fairness`, audited `provider.fairness_set`,
blocked under read-only license degrade). An override field that is left unset
**inherits the deployment default** for that bound — so an override only changes
the bounds you explicitly name. (Stored override values must be positive; the
table enforces it.)

**The hot path never blocks on Postgres.** The first time the gate sees a
tenant it enforces the deployment defaults immediately, then fetches that
tenant's stored override **asynchronously**, off the admission path, and caches
it for one minute (a provider write invalidates the tenant's cache at once). If
the policy store is slow or erroring, the deployment defaults keep applying — a
down database must never stall ingest. Availability first; bounds still
enforced.

## Anti-starvation properties (by design)

- **Deficit buckets.** A single batch larger than the burst capacity is still
  admitted while the bucket holds any tokens, driving the balance negative; the
  refill then claws it back. So the long-run rate stays bounded at the limit,
  but no batch size is *permanently* starved.
- **Rate and concurrency, never total volume.** A legitimately busy tenant
  running at or under its sustained budget is never rejected (asserted by test).
  The limits cap the *rate*, not the lifetime amount.
- **Bounded, not banned.** A shed or rejected tenant recovers at its configured
  rate the instant the burst window passes — there is no penalty box.
- **Never silent.** Every shed unit and every rejected query is counted per
  tenant and is visible in all three surfaces.

## Surfaces

- `GET /v1/fairness` (core; permission `fairness.read`, seeded to the admin
  role) — the caller's effective policy plus its accounting.
  `{"enforcing": false}` when the deployment runs with the gate unwired.
- `GET /provider/v1/fairness` (commercial) — every tenant the gate has seen:
  accounting, effective policy, and the stored overrides.
- `PUT /provider/v1/tenants/{id}/fairness` (commercial; admin operator) — tune a
  tenant's policy; enforced on its next admission.
- TSDB series (all per tenant, Grafana-federable):
  `probectl_fairness_admitted_units_total` and
  `probectl_fairness_shed_units_total` (both labeled `{tenant_id, meter}`),
  `probectl_fairness_queries_allowed_total`,
  `probectl_fairness_queries_rejected_total`, and
  `probectl_fairness_queries_in_flight` (labeled `{tenant_id}`).

## Configuration (deployment defaults)

| Key | Default | Meaning |
|---|---|---|
| `PROBECTL_FAIRNESS_RESULTS_PER_SEC` | `1000` | per-tenant result rate |
| `PROBECTL_FAIRNESS_FLOW_EVENTS_PER_SEC` | `10000` | per-tenant flow-record rate |
| `PROBECTL_FAIRNESS_INGEST_BYTES_PER_SEC` | `2097152` (2 MiB/s) | per-tenant ingest byte rate |
| `PROBECTL_FAIRNESS_DEVICE_METRICS_PER_SEC` | `2000` | per-tenant device (SNMP/gNMI) sample rate |
| `PROBECTL_FAIRNESS_BURST_SECONDS` | `10` | bucket capacity multiplier (capacity = rate × this) |
| `PROBECTL_FAIRNESS_QUERY_CONCURRENCY` | `0` (unlimited) | per-tenant in-flight query cap |
| `PROBECTL_FAIRNESS_QUERIES_PER_MIN` | `0` (unlimited) | per-tenant query budget |

These keys take positive numbers only. Raise a ceiling for a deployment whose
tenants legitimately run hotter; lower it to tighten the wall.

## Relationship to neighbors

- **Quotas** gate resource *creation* (agents, tests) and **never** drop
  telemetry; fairness bounds *rates* on the shared pipeline. They share the meter
  vocabulary. See [`docs/metering.md`](metering.md).
- **Siloed mode** is the *hard*-isolation answer (separate schemas/databases per
  tenant); fairness is what keeps *pooled* mode safe. See
  [`docs/isolation.md`](isolation.md).
- **The load gate** grows out of the same idea: its noisy-neighbor test (a heavy
  tenant running at 50× a modest tenant's volume must not breach the modest
  tenant's per-message latency) is the seed of the multi-tenant load test. See
  [`docs/scale-gate.md`](scale-gate.md).
