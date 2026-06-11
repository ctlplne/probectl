# Tenant isolation models

"Isolation model" answers a simple question: **how physically separate is one
tenant's data from another's?** (A **tenant** is one isolated
customer/organization sharing the deployment — the outermost security boundary
in probectl.) probectl offers three answers, and you can pick
per deployment *and* per tenant — a single install can run most tenants pooled
and a few high-compliance ones siloed. This page covers the *models*; the
storage-layer enforcement mechanics they all share (forced RLS, partition keys,
the cross-tenant test suite) live in
[`security/tenant-isolation.md`](security/tenant-isolation.md).

The mental model is a spectrum:

- **Pooled** — everyone shares the same tables/databases/topics, told apart by
  `tenant_id`. Cheapest, densest, and the **default**. Stays core (free).
- **Siloed** — each tenant gets its own Postgres schema, ClickHouse database, bus
  topics, and object-store namespace. The strongest separation.
- **Hybrid** — pooled control plane (the cheap, shared part) but a *per-tenant*
  ClickHouse database for the high-volume flow telemetry. A middle ground.

As housing: pooled is an apartment building — one structure, a hard lock on
every unit; siloed is a street of detached houses; hybrid is an apartment with
a detached private garage for the bulky stuff (the flow telemetry). The
spectrum trades cost and density against physical distance.

Siloed and hybrid are `ee/` features, unlocked by the `siloed_isolation` license
feature (an MSP-tier capability); pooled always works regardless of license.

Reading the table needs three terms. **RLS** is Postgres Row-Level Security:
the database itself appends an invisible tenant filter to every statement, so
even an unscoped `SELECT` returns only the current tenant's rows — or nothing,
when no tenant is bound. A **partition key** is the column ClickHouse uses to
decide which physical chunk of disk a row lands in — partitioning by
`tenant_id` keeps each tenant's rows physically grouped. The **bus** is the
publish/subscribe message pipe between producers and the control plane; its
named channels are **topics**.

| Model | Postgres (control/config state) | ClickHouse (flows) | Bus topics | Object store |
|---|---|---|---|---|
| **pooled** (default) | shared tables, RLS keyed on the per-transaction tenant setting | shared table, `tenant_id` partition key | shared topics, tenant-keyed messages | shared backend, `tenant/<id>/` key prefix |
| **hybrid** | **pooled** (shared control plane, by design) | **per-tenant database**, optionally on a residency data plane | **per-tenant namespaced topics** | per-tenant `silo/<id>/` key namespace |
| **siloed** | **per-tenant schema** (tenant-owned tables copied in; RLS recreated inside) | per-tenant database (+ data plane) | per-tenant namespaced topics | per-tenant key namespace |

**The key idea: physical separation is layered *on top of* the pooled scoping,
never *instead of* it.** A siloed schema still re-creates the
`tenant_isolation` RLS policies, every transaction still binds the tenant setting,
bus messages stay tenant-keyed, and every read is still tenant-scoped at the query
layer. So even if routing sent a query to the wrong silo, the query would return
*nothing* rather than another tenant's rows — walking into the wrong house still
leaves you facing a locked safe whose key you don't hold. The defenses stack,
they don't replace each other.

**Fail closed on routing — everywhere, including the bus.** ("Fail closed":
when the system cannot prove the safe answer, it refuses the operation rather
than guessing.) The isolation router
(`ee/silo.Router`, installed at the editions attach seam) resolves each tenant's
storage targets from the tenant registry. A routing **error fails the
operation** — a siloed tenant is never silently downgraded to the pooled stores,
and a pooled query can never reach a siloed tenant's stores.
(`tenancy.InTenant` resolves targets *before* opening the transaction; the flow
store splits a batch per target and fails the whole batch on a routing error.)
Bus lanes are no exception: if a siloed tenant's lane cannot be resolved when a
result arrives, the control plane **drops that result with a loud error** rather
than publishing it onto the shared topic
(`internal/agenttransport/service.go`) — a siloed tenant's telemetry must never
silently ride the shared lane. Think of a courier with an unreadable address
label: the parcel goes back to the depot, never onto the public loading dock.
Availability comes from the *agent*, not from a
fallback: the agent's store-and-forward buffer (the depot) retries delivery, so
a transient routing blip delays the data instead of mis-routing it.

## How each leg works

- **Postgres (siloed):** each tenant gets a schema named `t_<uuid>` (the tenant
  UUID lowercased, dashes stripped — `silo.SchemaName`) containing every
  tenant-owned table. The table set is *derived live* from
  `information_schema` — any `public` table with a `tenant_id` column, minus a
  provider-owned deny list — so the silo automatically tracks whatever tables the
  schema actually has. Each table is created `LIKE public.<t> INCLUDING ALL`, with
  the RLS policy recreated and the app-role grants applied. `tenancy.InTenant`
  routes a siloed tenant by running `SET LOCAL search_path TO <schema>, public`,
  so global tables (permissions, tenants) still resolve in `public`.
- **ClickHouse:** a per-tenant database `probectl_t_<uuid>` holding the same flow
  table; inserts are split per target and reads route by the query's tenant. With
  a **residency** pin, both run against that data plane's ClickHouse URL.
- **Bus:** topics gain a namespace segment, e.g.
  `probectl.t-<slug>.network.results`. The control plane publishes a siloed
  tenant's results/RUM onto its own lane and subscribes to every siloed lane known
  at startup. (A tenant siloed *after* boot is picked up from its lane after the
  next restart; the shared lanes stay subscribed throughout, so nothing is
  dropped.)
- **Object store:** keys move under `silo/<tenant-id>/…` (the pooled layout is
  `tenant/<id>/…`). Note the honesty caveat below: in this release that is a key
  *namespace* on the same backend, not a separate storage system.

## Residency: exactly what is and is not pinned

**Residency** is a legal or contractual constraint on *where* — which
jurisdiction's hardware — data may be stored. This section is deliberately
precise because **a residency claim you cannot back
up is a compliance liability.** `PROBECTL_DATAPLANES` names the available planes
(e.g. `eu=https://ch-eu:8123;us=https://ch-us:8123`); a siloed or hybrid tenant
provisioned with `residency: eu` gets its ClickHouse database **created on and
routed to** that plane.

**Pinned today:** the tenant's ClickHouse flow data — the high-volume telemetry
store, which is what residency rules usually care about most.

**Not pinned today** (and you should not claim otherwise): the Postgres
control/config state (it is a shared control plane), the metrics TSDB (metrics
stay tenant-labeled in the deployment's TSDB), the object store
(namespace-isolated on a single backend), and the bus brokers. Multi-region
control-plane and HA mechanics are covered separately in
[`multi-region.md`](multi-region.md); per-tenant encryption keys are a separate
capability ([`byok.md`](byok.md)).

## ClickHouse database-level tenancy

Code-level scoping is the first line of defense — every flow/path query pins a
`tenant_id`, and an unscoped call refuses with `ErrNoTenant`. But that only
protects access *through probectl*. To also protect a tenant credential used
*directly* against ClickHouse, `EnsureRowPolicies` installs **database-level row
policies** (a **row policy** is ClickHouse's analogue of Postgres RLS — a
server-side filter attached to the table itself): per shared table, a policy
filtering every user to `tenant_id =
currentUser()` (by convention each per-tenant ClickHouse user is named exactly the
tenant id), plus a permissive policy for probectl's own service account. So even
someone holding a tenant's raw ClickHouse credentials cannot read another tenant's
rows — the guarantee holds independently of this codebase. The cross-tenant CI
gate exercises flowstore + pathstore against a *real* ClickHouse to prove it.

## Lifecycle

Provisioning a tenant (`POST /provider/v1/tenants` with `isolation_model` +
`residency`, or the console's Isolation selector) creates the isolated stores
**before the call returns** — a siloed tenant never exists without its silo. A
provisioning failure is loud, and because the DDL — the CREATE/ALTER/DROP class
of SQL statements — is **idempotent** (safe to run twice; a second run finds the
work already done), the call is simply
re-runnable. Offboarding **tears the isolated stores down** (`DROP SCHEMA …
CASCADE`, `DROP DATABASE`) — they are per-tenant containers, safe to drop. Pooled
rows (a hybrid tenant's shared control state) are left untouched; their export and
verifiable deletion is the separate compliance flow. Teardown is idempotent too: a
partial failure is fixed by calling offboard again.

## Migrations across silos (the operational cost of siloed)

This is the price you pay for siloing: migrations are written against `public`, so
every silo schema has to be brought up to the current shape separately. probectl
does this by **catch-up** — it re-derives the tenant-owned table set, creates any
missing tables (the same `LIKE` + RLS recipe), and adds any missing columns (an
`information_schema` diff). This works because the migration gate only admits
**expand-only** changes (see [`lifecycle.md`](lifecycle.md)): create-missing +
add-missing-columns covers every migration the gate allows. The rarer
destructive "contract" phases (drops/renames) are run by the operator across
silos. Catch-up runs **automatically at startup for every siloed tenant** and is
idempotent, and per-tenant **drift** — the gap between a silo's schema and the
current `public` shape — is computable (`DriftFor`) so the lag is always
*visible*, never silent. The window between a freshly-deployed replica writing a
new `public` table and an old silo catching up is bounded by the deploy itself —
roll the control plane, then let catch-up converge.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_DATAPLANES` | (none) | named residency planes: `name=clickhouseURL[;…]` |

Everything else rides existing keys (`PROBECTL_FLOWSTORE_*`, and
`PROBECTL_FLOW_RETENTION_DAYS` applies to per-tenant databases too). Siloed and
hybrid provisioning requires a license granting `siloed_isolation`; without it
those models are refused (pooled always works). See [`configuration.md`](configuration.md).

## Tests

Unit tests cover the planner/catch-up/teardown DDL recipes, naming, drift
diffing, router fail-closed semantics, flow-store routing (per-target inserts,
pinned planes, malformed-name refusal), topic naming, and the provider-API
lifecycle (license gating, residency validation, teardown-on-offboard, and
pooled↔siloed handler parity). The headline integration test (live Postgres) is
`TestSiloedPhysicalSeparation`, which asserts: schema creation; **physical
separation** (a siloed tenant's rows exist only in its schema — zero in `public`,
and vice versa); pooled↔siloed **parity** of the same tenant-scoped operation;
in-silo RLS defense-in-depth; router correctness; **catch-up** after a simulated
later migration; and **teardown** (gone, idempotent, pooled data untouched).
