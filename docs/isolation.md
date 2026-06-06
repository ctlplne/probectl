# Tenant isolation models (S-T2, F52)

probectl supports three isolation models, selectable **per deployment and per
tenant**. Pooled is the default and stays core (CLAUDE.md §2, ratified);
siloed and hybrid are `ee/` features unlocked by the `siloed_isolation`
license feature (MSP bands).

| Model | Postgres (control/config state) | ClickHouse (flows) | Bus topics | Object store |
|---|---|---|---|---|
| **pooled** (default) | shared tables, RLS keyed on the per-tx tenant GUC | shared table, `tenant_id` partition key | shared topics, tenant-keyed messages | shared backend, `tenant/<id>/` key prefix |
| **hybrid** | **pooled** (shared control plane by design) | **per-tenant database**, optionally on a residency data plane | **per-tenant namespaced topics** | per-tenant `silo/<id>/` key namespace |
| **siloed** | **per-tenant schema** (tenant-owned tables copied; RLS recreated inside) | per-tenant database (+ data plane) | per-tenant namespaced topics | per-tenant key namespace |

**Defense-in-depth, not replacement.** Physical separation is added ON TOP of
the pooled scoping: silo schemas re-create the `tenant_isolation` RLS policies
and every transaction still binds the tenant GUC; bus messages stay
tenant-keyed; every read remains tenant-scoped at the query layer. A
mis-routed query therefore still returns nothing rather than another tenant's
rows.

**Fail closed.** The isolation router (`ee/silo.Router`, installed at the
attach seam) resolves every tenant's targets from the tenant registry. A
routing **error fails the operation** — a siloed tenant is never silently
degraded to the pooled stores, and a pooled query can never touch a siloed
tenant's stores (`tenancy.InTenant` resolves targets before opening the
transaction; the flow store splits batches per target and fails the batch on
a routing error). The single deliberate exception: **bus lanes** degrade to
the shared topic on a routing blip (availability-first), because the lane is
delivery routing — the tenant boundary is the tenant-keyed message plus
storage-level isolation, which both hold regardless.

## How each leg works

- **Postgres (siloed):** a per-tenant schema `t_<uuid>` containing every
  tenant-owned table (derived live from `information_schema`: any public
  table with a `tenant_id` column, minus the provider-owned deny list), each
  created `LIKE public.<t> INCLUDING ALL` with the RLS policy recreated and
  app-role grants applied. `tenancy.InTenant` routes via
  `SET LOCAL search_path TO <schema>, public` — global tables (permissions,
  tenants) still resolve in public.
- **ClickHouse:** per-tenant database `probectl_t_<uuid>` with the same flow
  table; inserts split per target; reads route by the query's tenant. With a
  **residency** pin, both run against that data plane's ClickHouse URL.
- **Bus:** topics gain a namespace segment:
  `probectl.t-<slug>.network.results`. The control plane publishes
  tenant-scoped results/RUM onto the tenant's lane and subscribes to every
  siloed tenant's lanes known at startup (a tenant siloed after boot is
  consumed from its lane after the next restart; the shared lanes stay
  subscribed throughout).
- **Object store:** keys move under `silo/<tenant-id>/…` (the pooled layout
  is `tenant/<id>/…`). Same backend in this release — see honesty below.

## Residency: exactly what is and is not pinned

`PROBECTL_DATAPLANES` names the planes ("eu=https://ch-eu:8123;us=…"); a
siloed/hybrid tenant provisioned with `residency: eu` gets its ClickHouse
database **created on and routed to** that plane.

**Pinned in S-T2:** the tenant's ClickHouse flow data (the high-volume
telemetry store).
**NOT pinned in S-T2** (documented per the watch-out — residency claims must
be real): Postgres control/config state (shared control plane), the TSDB
(metrics stay tenant-labeled in the deployment TSDB), the object store
(namespace-isolated, single backend), and bus brokers. Multi-region
control/HA mechanics are S-EE2; per-tenant keys are S-T6. Do not sell
residency beyond this list.

## ClickHouse DB-level tenancy (U-026)

Code-level scoping (every query pins `tenant_id`, unscoped calls refuse with
`ErrNoTenant`) is backed by **DB-level row policies** for direct CH access:
`EnsureRowPolicies` installs, per shared table, a policy filtering every user
to `tenant_id = currentUser()` (convention: per-tenant CH users are named
exactly the tenant id) plus a permissive policy for probectl's own service
account. A tenant credential used directly against ClickHouse can then never
read another tenant's rows — independent of this codebase. The cross-tenant
CI gate runs flowstore + pathstore against a real ClickHouse.

## Lifecycle

Provisioning (`POST /provider/v1/tenants` with `isolation_model` +
`residency`, or the console's Isolation selector) creates the isolated
stores **before** the call returns — a siloed tenant never exists without
its silo; a provisioning failure is loud and the call is re-runnable
(idempotent DDL). Offboarding **tears the isolated stores down**
(`DROP SCHEMA … CASCADE`, `DROP DATABASE`) — they are per-tenant containers;
pooled rows (hybrid control state) are untouched and their export/verifiable
deletion is the S-T5 compliance flow. Teardown is idempotent: a failure is
retried by calling offboard again.

## Migrations across silos (the operational cost of siloed)

Migrations apply to `public`. Silo schemas are brought up to the current
shape by **catch-up**: re-derive the tenant-owned set, create missing tables
(the same LIKE+RLS recipe), and add missing columns (an `information_schema`
diff). Because the S34 migration gate enforces **expand-only** changes,
create-missing + add-missing-columns covers every migration the gate admits;
contract phases (drops/renames) are operator-run across silos per the S34
contract procedure. Catch-up runs automatically **at startup for every
siloed tenant** and is idempotent; per-tenant drift is computable
(`DriftFor`) so the lag is visible, never silent. The window between a new
replica writing a new public table and an old silo catching up is bounded by
the deploy itself — roll the control plane, then trust catch-up.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_DATAPLANES` | (none) | named residency planes: `name=clickhouseURL[;…]` |

Everything else rides existing keys (`PROBECTL_FLOWSTORE_*`,
`PROBECTL_FLOW_RETENTION_DAYS` applies per-tenant databases too). Siloed and
hybrid provisioning requires a license granting `siloed_isolation`; without
it the models are refused (pooled always works).

## Tests

Unit: the planner/catch-up/teardown DDL recipes, naming, drift diffing,
router fail-closed semantics, flow-store routing (per-target inserts, pinned
planes, malformed-name refusal), topic naming, and the provider-API
lifecycle (license gating, residency validation, teardown-on-offboard,
pooled↔siloed handler parity). Integration (live Postgres):
`TestSiloedPhysicalSeparation` — schema creation, **physical separation**
(a siloed tenant's rows exist only in its schema; zero rows in public, and
vice versa), pooled↔siloed **parity** of the same tenant-scoped operation,
in-silo RLS defense-in-depth, router truth, **catch-up** after a simulated
later migration, and **teardown** (gone, idempotent, pooled data untouched).
