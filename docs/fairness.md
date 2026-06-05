# Tenant fairness / noisy-neighbor isolation (S-T7, F57)

In a pooled deployment one tenant must not be able to degrade the others.
probectl bounds each tenant's use of the shared platform with **per-tenant
fairness policies** — ingest rate bounds, query-cost guards, and full
accounting — enforced in **core** (the protection belongs to the platform
itself, in every edition); only the cross-tenant operator views and the
tuning surface ride the provider plane (`ee/`, `provider_plane` feature).

## The three mechanisms

**Ingest rate bounds.** Token buckets per (tenant, meter) wrap the result and
flow consumers — admission happens BEFORE the expensive section (decode →
enrich → store write), so an over-rate tenant's burst is shed in O(1) and
never stalls the shared pipeline. Because the gate wraps the *consumer*, the
bound behaves identically under Kafka and the lightweight bus modes. Meters
share the S-T3 usage vocabulary: `results_ingested`, `flow_events`,
`ingest_bytes`. Shed messages are not metered for billing — billing reflects
stored work; fairness accounting records the shed.

**Query-cost guards.** Per-tenant in-flight concurrency + a per-minute query
budget on the S23 query surfaces (`/v1/ai/ask`, the Grafana-compatible
`query`/`query_range` proxy, the MCP events tool) — extending S23's
deployment-wide row/timeout guards with a *tenant* dimension. Rejections are
**429 `rate_limited` with `Retry-After`**: an over-budget tenant gets a clear
signal, never a slow platform for everyone.

**Accounting.** Per-tenant admitted/shed/rejected counters surface in three
places: `GET /v1/fairness` (the tenant's own view — debugging a fairness
dispute never requires the provider's word), the provider console's Fairness
card (ee), and as TSDB series (`probectl_fairness_*{tenant_id,meter}`,
Grafana-federable; written every 30s).

## The policy model

A policy is a set of bounds; **zero/unset means unlimited** — fairness is
opt-in per bound, so small and single-tenant deployments enforce nothing
unless configured.

| Field | Meaning |
|---|---|
| `results_per_sec` | result messages admitted per second |
| `flow_events_per_sec` | flow records admitted per second |
| `ingest_bytes_per_sec` | result payload bytes admitted per second |
| `burst_seconds` | bucket capacity = rate × burst (default 10) |
| `query_concurrency` | max in-flight queries |
| `queries_per_min` | query budget (bucket capacity = one full minute) |
| `weight` | operator vocabulary for relative share (recorded, not yet gating) |

Resolution: deployment defaults come from `PROBECTL_FAIRNESS_*`; per-tenant
overrides live in `tenant_fairness` (migration 0031) and are set from the
provider console (`PUT /provider/v1/tenants/{id}/fairness`, audited
`provider.fairness_set`, blocked by the read-only license degrade). Unset
override fields inherit the deployment defaults.

**The hot path never blocks on Postgres:** stored overrides are fetched
asynchronously with a one-minute cache (a provider write invalidates the
tenant immediately); until the first fetch — and whenever the policy store
errors — the deployment defaults apply. Availability first, bounds still
enforced.

## Anti-starvation properties (the watch-outs, by design)

- **Deficit buckets:** a batch larger than the burst capacity is admitted
  while the bucket is positive and drives it negative, repaid by refill —
  long-run rate is bounded at the limit, but no batch size is permanently
  starved.
- **Rate + concurrency, never volume:** a legitimately-busy tenant running at
  or under its sustained budget is never rejected (asserted by test).
- **Bounded, not banned:** shed/rejected tenants recover at their configured
  rate the moment the burst window passes.
- **Never silent:** every shed unit and rejected query is counted per tenant
  and attributable in all three surfaces.

## Surfaces

- `GET /v1/fairness` (core, permission `fairness.read`, admin-seeded): the
  caller's effective policy + accounting; `{"enforcing": false}` when the
  deployment runs ungated.
- `GET /provider/v1/fairness` (ee): every seen tenant's accounting +
  effective policy, plus stored overrides.
- `PUT /provider/v1/tenants/{id}/fairness` (ee, admin operator): tune a
  tenant's policy; enforced on the next admission.
- TSDB series: `probectl_fairness_admitted_units_total`,
  `probectl_fairness_shed_units_total` (both `{tenant_id, meter}`),
  `probectl_fairness_queries_allowed_total`,
  `probectl_fairness_queries_rejected_total`,
  `probectl_fairness_queries_in_flight` (`{tenant_id}`).

## Configuration (deployment defaults)

| Key | Default | Meaning |
|---|---|---|
| `PROBECTL_FAIRNESS_RESULTS_PER_SEC` | 0 (unlimited) | per-tenant result rate |
| `PROBECTL_FAIRNESS_FLOW_EVENTS_PER_SEC` | 0 | per-tenant flow-record rate |
| `PROBECTL_FAIRNESS_INGEST_BYTES_PER_SEC` | 0 | per-tenant ingest byte rate |
| `PROBECTL_FAIRNESS_BURST_SECONDS` | 10 | bucket capacity multiplier |
| `PROBECTL_FAIRNESS_QUERY_CONCURRENCY` | 0 | per-tenant in-flight query cap |
| `PROBECTL_FAIRNESS_QUERIES_PER_MIN` | 0 | per-tenant query budget |

## Relationship to neighbors

- **S-T3 quotas** gate resource *creation* (agents, tests) and **never** drop
  telemetry; fairness bounds *rates* on the shared pipeline. They share the
  meter vocabulary.
- **S-T2 siloed mode** is the hard-isolation answer; fairness is what keeps
  *pooled* mode safe.
- **S48 load gate:** the noisy-neighbor unit test (a heavy tenant at 50× a
  modest tenant's volume must not breach the modest tenant's per-message
  latency SLO) is the seed of the S48 multi-tenant load-test gate.
