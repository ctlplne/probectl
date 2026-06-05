# Per-tenant metering, usage & billing export (S-T3, F53)

The MSP-tier metering plane: per-tenant usage counters and snapshots, a
usage/showback API, per-tenant creation quotas, and a billing-export feed for
the MSP's existing PSA/billing system. Lives in **`ee/billing`**, unlocked by
the `metering` license feature; community/unlicensed deployments meter
nothing (the core seam is a no-op) and the provider-console usage surfaces
stay hidden.

probectl deliberately does **not** build an invoicing engine — it exports.
The ratified first export target is **generic CSV + JSON Lines** (vendor-
neutral; every PSA imports CSV). Vendor-shaped connectors (ConnectWise,
Autotask, Stripe) are follow-ups once a design partner names one.

## The meters

| Meter | Kind | Unit | Source |
|---|---|---|---|
| `agents` | gauge | count | snapshot: counted inside the tenant's own scope |
| `tests` | gauge | count | snapshot: counted inside the tenant's own scope |
| `results_ingested` | counter | count | the result pipeline, as results flow |
| `ingest_bytes` | counter | bytes | result payload bytes, same stream |
| `flow_events` | counter | count | flow batches landing in the flow store |
| `ai_calls` | counter | count | AI assistant questions |

Metering derives from the tenant-tagged streams **already flowing** (the
`internal/usage` seam in the pipeline/AI paths) — never a parallel pipeline.
Counters bucket **hourly at record time** and flush every minute; a failed
flush merges deltas back and retries (billing-critical losslessness: counts
are delayed, never lost, never doubled — the flush batch is one transaction).

**Accuracy / reconciliation (the watch-out):** gauges ARE the
source-of-truth counts — the collector runs `count(*)` per tenant **inside
that tenant's own scope** (`tenancy.InTenant`: RLS-bound, silo-routed), so
there is no cross-tenant read path, and a siloed tenant's resources are
counted exactly once, in its own schema. No double-counting across
pooled/siloed by construction.

## Usage API + export feed (the contract)

Provider-plane routes (operator session; hidden 404 when unlicensed):

- `GET /provider/v1/usage?from&to&tenant_id&rollup=hour|day` — UsageRecords
  (defaults: month-to-date, day rollup). Counters **sum** across periods;
  gauges take the **peak** (the fair capacity snapshot).
- `GET /provider/v1/usage/export?format=csv|jsonl&…` — the billing feed.
  **Stable column contract** (additive changes only):

```
tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit
```

Timestamps are RFC 3339 UTC. JSONL carries the same field names, one object
per line. Records persist in `usage_records` (migration 0026): provider-plane
billing data about tenants — written/read by the `probectl_provider` role via
an explicit policy, still tenant-RLS'd so a tenant can read its own usage,
and **never copied into silo schemas** (billing stays pooled by design).

## Quotas

`tenant_quotas` (per tenant): `max_agents`, `max_tests` — `null` = unlimited.
Managed by **admins** (SoD; audited as `provider.quota_set`; the read-only
license ladder blocks quota writes) via
`GET/PUT /provider/v1/tenants/{id}/quotas` or the console's Usage card.

**Semantics (the house doctrine):**

- Quotas gate **control-plane resource creation only**: creating a test
  (403 `quota_exceeded`) and registering a **new** agent
  (gRPC `ResourceExhausted`). An existing agent re-registering is never
  rejected — a running fleet must not break on restart.
- **Telemetry is never quota-dropped.** Fairness throttling of pooled ingest
  is S-T7's job.
- Enforcement counts live state inside the tenant's scope (exact, not
  cached); quota lookups cache 30s and invalidate on update.
- Infrastructure failures **degrade open**: a quota is a billing control,
  not a security boundary.

## Console

The provider console's **Usage & showback** card: month-to-date per-tenant
meters, one-click CSV/JSONL export, and (admins) the per-tenant quota editor.
Hidden entirely when the metering feature is not licensed.

## Configuration

No keys. Flush (1m) and snapshot (15m) cadences are fixed; the feature
activates with a license granting `metering` (provider/MSP tier). Quotas and
usage live in Postgres alongside the tenant registry.
