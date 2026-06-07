# Tenant isolation — the storage-layer threat model

Tenant isolation is probectl's outermost security boundary (CLAUDE.md §7
guardrail 1). This page documents how the **database layer** enforces it
beneath the application — the defense that holds when an application check is
missing or the app is compromised — and, honestly, what each store's
privileged accounts can still do.

## Postgres (durable state: tenants, agents, incidents, RBAC, audit, SLOs)

**Enforcement: Row-Level Security, forced.** Every tenant-owned table carries a
non-null `tenant_id` and a `tenant_isolation` policy keyed to the
`probectl.tenant_id` GUC. `internal/tenancy.InTenant` opens a transaction,
`SET LOCAL ROLE probectl_app`, sets the GUC, and runs the repository — so a
predicate-free `SELECT *` still returns only the caller's rows.

**Why it holds (TENANT-104):**

- `probectl_app` is `NOSUPERUSER NOBYPASSRLS` (migration 0007). A superuser or
  a `BYPASSRLS` role would read across tenants regardless of policies.
- Tenant tables use **FORCE ROW LEVEL SECURITY**, so even the table *owner* is
  bound (plain `ENABLE` exempts the owner — the subtle gap the audit named).
- **Boot self-check** (`tenancy.AssertIsolationPosture`, run from `main`
  before serving): assumes `probectl_app`, and FATALs if the effective role is
  super or bypass-RLS, or if any `tenant_id` table lacks FORCE RLS, or if no
  tenant tables are found (migrations not applied). A deployment with RLS
  silently off cannot serve traffic. The `isolation` CI suite proves the check
  passes on a migrated DB and *rejects* an unforced table (non-vacuous).

**The provider plane** uses a separate least-privilege role (`probectl_provider`,
`NOBYPASSRLS`) granted only operational-metadata tables (fleet/lifecycle), never
telemetry — `tenancy.InProvider`. It sets no tenant GUC, so the per-tenant
policies match nothing and only the explicit provider policies apply.

## ClickHouse (high-volume telemetry: flow, path, threat, change, cost)

**Application layer (always on):** every tenant-scoped query leads with
`WHERE tenant_id = <caller>`; an unscoped query is refused in code
(`ErrNoTenant`). This is the primary boundary in the default deployment.

**DB layer — per-tenant direct-access policy (U-026, shipped):**
`EnsureRowPolicies` installs `probectl_tenant_isolation` (`USING tenant_id =
currentUser()`) so an operator connecting with a **per-tenant ClickHouse
credential** (the siloed/direct-access convention in `docs/isolation.md`)
cannot cross tenants — independent of probectl's code.

**DB layer — query-path scoping for the pooled service account (TENANT-102):**
The honest gap the second audit named: probectl's own pooled deployment holds
**one** service credential, and that account is policy-exempt
(`probectl_service_access USING 1`) because it must insert, migrate, and run
admin counts across tenants. So if app-layer `WHERE` scoping were bypassed
(a code bug, an injection), the service account could read cross-tenant.

The backstop, opt-in via `PROBECTL_FLOWSTORE_TENANT_SCOPING=true`:

1. Every tenant-scoped **read** attaches a per-request custom setting
   `SQL_probectl_tenant=<tenant>` (admin/cross-tenant reads — migrations,
   global counts — pass no setting, by design).
2. A dedicated **reader user** (`PROBECTL_FLOWSTORE_READER_USER`, e.g.
   `probectl_reader`) gets `EnsureReaderRowPolicy`:
   `probectl_reader_scope … FOR SELECT USING tenant_id =
   getSetting('SQL_probectl_tenant')` — no permissive escape. With the reader
   user's custom setting **defaulting to `''`** server-side, an unset or
   dropped setting matches **no rows**: fail closed.
3. Production routes tenant **data reads through the reader user**; the
   write/service user keeps full access for inserts + migrations only. A
   compromised query path that omits the `WHERE` then still cannot cross
   tenants — the reader policy constrains it at the DB.

Operator prerequisites (documented, not auto-configured): allow the custom
setting prefix (`<custom_settings_prefixes>SQL_</custom_settings_prefixes>`),
create the reader user with a default `SQL_probectl_tenant = ''`, and grant it
`SELECT` only. Until enabled, the app-layer `WHERE` is the boundary and the
service account remains read-capable across tenants — stated plainly so it is
never a surprise.

**What the service/write account can still do (residual, by design):** insert
into any tenant's partition, run cross-tenant counts, and (without the reader
split) read across tenants. This is required for ingest, migrations, and
retention. It is bounded by: the application never issuing an unscoped read,
the secret-management of that single credential, and — when enabled — the
reader split removing it from the read path entirely.

## At-rest encryption (sensitive tenant-owned values)

Sensitive columns (alert-channel secrets, …) are sealed through
`internal/tenantcrypto` (the deployment envelope, or the licensed per-tenant
keyring/BYOK). Keyless dev runs passthrough, kept honest by the self-describing
stored format.

**Fail closed (TENANT-106):** `PROBECTL_REQUIRE_AT_REST_ENCRYPTION=true` makes
keyless passthrough a **fatal startup error** — the control plane refuses to
run without a resolvable key rather than silently writing plaintext. Set it in
the hardened/regulated profiles. Off by default so keyless local dev still
boots.

## Verification

- `internal/tenancy` (`-tags isolation`): RLS posture pass + non-vacuous
  rejection; cross-tenant query returns nothing (the standing
  `cross-tenant-isolation` CI gate).
- `internal/store/flowstore`: read-path setting attach, reader-policy DDL
  shape (no permissive escape), empty-reader rejection; and (`-tags
  isolation`) a non-service CH reader issuing a **predicate-free** read sees
  only its own tenant's rows — the row policy, not the app WHERE, scopes it.
- `internal/pipeline` (`-tags isolation`): end-to-end ingest injection —
  flow through real ClickHouse, device + eBPF/endpoint results through the
  RLS-scoped registry binding on real Postgres — a payload claiming another
  tenant is rejected and never lands in the victim partition; the registry
  lookup itself is proven tenant-scoped. Plus (no infra) siloed records
  route only to namespaced topics, with RED-006 fail-closed construction.
- `internal/otel/otlp` (`-tags isolation`): an OTLP push authenticated as one
  tenant but naming another is rejected; the sink only ever sees the
  authenticated tenant.
- `internal/config`: the `require-at-rest` and CH-scoping knobs parse and
  default off.
