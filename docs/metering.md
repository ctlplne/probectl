# Per-tenant metering, usage & billing export

## What this is

When an MSP (managed service provider) self-hosts probectl and serves many
tenants, it needs to answer "how much did each tenant use this month?" — to
bill them. **Metering** is that counting: recording each tenant's usage,
accurately enough to invoice from. This is the plane that produces those
numbers: per-tenant usage counters and snapshots, a usage/showback API
(showback — showing each tenant its consumption without probectl doing the
charging), per-tenant creation quotas (a quota — a cap on how many of a
resource a tenant may create), and a billing-export feed the MSP feeds into its
existing professional-services-automation (PSA) or billing system.

It is a **commercial (Provider/MSP tier)** feature. The implementation lives in
`ee/billing` and is unlocked by the `metering` license feature; the core
platform ships only an inert seam (`internal/usage`). A community or unlicensed
deployment therefore **meters nothing** — the seam is a no-op that records
nothing and allows everything — and the provider-console usage surfaces stay
hidden. (For why the line is drawn here, see
[`docs/editions.md`](editions.md).)

probectl deliberately does **not** build an invoicing engine — it *exports*. The
first export target is **generic CSV + JSON Lines**: vendor-neutral, because
every PSA imports CSV. Vendor-shaped connectors (ConnectWise, Autotask, Stripe)
are follow-ups, to be built once a design partner names the one they need.

## The meters

There are two kinds of meter, and the distinction drives everything downstream:
a **counter** only ever goes up (you sum it over a period), and a **gauge** is a
point-in-time level (you take the peak over a period). A counter is a car's
odometer — it only climbs, and "how far this month" is a sum; a gauge is the
fuel gauge — a level at a glance, and the honest monthly question is "how full
did it get at most?"

| Meter | Kind | Unit | Source |
|---|---|---|---|
| `agents` | gauge | count | periodic snapshot, counted inside the tenant's own scope |
| `tests` | gauge | count | periodic snapshot, counted inside the tenant's own scope |
| `results_ingested` | counter | count | the result pipeline, as results flow |
| `ingest_bytes` | counter | bytes | result payload bytes, same stream |
| `flow_events` | counter | count | flow batches landing in the flow store |
| `ai_calls` | counter | count | AI assistant questions |

The counters are derived from the tenant-tagged streams that are **already
flowing** — the core call sites call the `internal/usage` seam as results, flow
batches, and AI questions pass through. There is no parallel metering pipeline.
Counters are bucketed **hourly at the moment of recording** (so an hour boundary
is exact regardless of when the buffer flushes), buffered in memory, and flushed
to Postgres every minute. If a flush fails, the buffered deltas are **merged
back** and retried on the next tick — billing-critical losslessness: counts can
be delayed, but never lost and never double-counted, because each flush is one
transaction.

### Why the gauges are exact

The gauges (`agents`, `tests`) are the source-of-truth counts, and they are
collected carefully. A snapshot collector lists the tenants, then counts each
tenant's resources by running `count(*)` **inside that tenant's own scope**
(`tenancy.InTenant`: bound by row-level security — RLS, where the database
itself filters every query to one tenant's rows — for pooled tenants,
schema-routed for siloed tenants). There is no cross-tenant read path at all,
so a siloed tenant's resources are counted exactly once, in its own schema, and
pooled and siloed tenants cannot double-count each other by construction.

## Usage API + export feed

These are provider-plane routes (operator session). When the `metering` feature
is not licensed they are hidden — a request gets a 404, not a 403, so the
feature's existence isn't even advertised.

- `GET /provider/v1/usage?from&to&tenant_id&rollup=hour|day` — usage records.
  Defaults are month-to-date with day rollup. Counters **sum** across the
  period; gauges take the **peak** (the fair capacity snapshot — you bill for
  the most agents a tenant ran, not their average).
- `GET /provider/v1/usage/export?format=csv|jsonl&…` — the billing feed
  (`csv` is the default). The column set is a **stable contract** — only
  additive changes are allowed, so an importer never breaks:

```text
tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit
```

Timestamps are RFC 3339 in UTC. JSON Lines carries the same field names, one
object per line.

Records persist in the `usage_records` table (migration `0026_metering.sql`).
This is provider-plane billing data *about* tenants: it is written and read by
the `probectl_provider` database role through an explicit row-level-security
policy, but it still carries the standard per-tenant policy too, so a tenant can
read **its own** usage through tenant-scoped paths. It is never copied into silo
schemas — billing stays pooled by design.

## Quotas

The `tenant_quotas` table (one row per tenant) holds `max_agents` and
`max_tests`; `null` means unlimited. Quotas are managed by an **admin** operator
(separation of duties; the action is audited as `provider.quota_set`; and when
the license has lapsed into read-only degrade, quota writes are blocked) via
`GET`/`PUT /provider/v1/tenants/{id}/quotas` or the console's Usage card.

What a quota does — and deliberately does not do:

- It gates **control-plane resource creation only**: creating a test (denied
  with `403 quota_exceeded`) and registering a **new** agent (denied with the
  gRPC `ResourceExhausted` status). An *existing* agent re-registering is never
  rejected — a running fleet must not break on a restart.
- **Telemetry is never quota-dropped.** Observability must not silently lose
  data; throttling pooled ingest is the fairness layer's job, not the quota
  layer's (see [`docs/fairness.md`](fairness.md)).
- Enforcement counts live state inside the tenant's own scope (exact, not
  cached); quota lookups cache for 30 seconds and invalidate immediately on
  update.
- An infrastructure failure (a database blip) **degrades open** — the create is
  allowed. A quota is a billing control, not a security boundary, and the
  metering trail still records what actually happened.

## Console

The provider console's **Usage & showback** card shows month-to-date per-tenant
meters, offers one-click CSV/JSONL export, and (for admins) the per-tenant quota
editor. It is hidden entirely when the `metering` feature is not licensed.

## Configuration

There are no configuration keys. The flush cadence (1 minute) and snapshot
cadence (15 minutes) are fixed; the feature activates when the license grants
`metering` (Provider/MSP tier). Quotas and usage live in Postgres alongside the
tenant registry.
