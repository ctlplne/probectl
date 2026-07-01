# Tenant isolation at the storage layer

Tenant isolation is probectl's outermost security boundary — the first of the
project's [non-negotiables](../../CONTRIBUTING.md): one tenant (one isolated
customer or organization sharing the deployment) must never read another
tenant's data, full stop.

Most apps enforce that kind of rule in handler code — a `WHERE tenant_id = ?`
on every query. That works right up until the day someone forgets the `WHERE`,
an injection slips through (crafted input that escapes its quoted slot and
becomes SQL syntax), or a bug routes a query to the wrong place. probectl
treats that day as inevitable and pushes the boundary **down into the database
itself**, so the data store refuses to hand over another tenant's rows even when
the application code above it is wrong. This is **defense-in-depth**: stacked,
independent layers, each built on the assumption that the layer above it has
already failed.

This page documents that database-layer defense store by store, and — because
honesty is the whole point of a security doc — exactly what each store's
privileged accounts can still do.

> **Scope note.** This is the storage-layer *threat model* — the mechanism and
> its residual risk. For the three deployment shapes (pooled / siloed / hybrid)
> and how to choose between them, see [../isolation.md](../isolation.md). The
> two docs are complementary; if anything here disagrees with the code, the code
> wins and that is a bug to file.

## Postgres — durable state (tenants, agents, incidents, RBAC, audit, SLOs)

**What:** every tenant-owned table is invisible across tenants at the row level,
enforced by Postgres itself, not by probectl.

**How — Row-Level Security, forced.** **Row-Level Security** (RLS) is a
Postgres feature: a *policy* attached to a table filters every row a query may
see or change, inside the database engine itself — below any application code.
Each tenant-owned table carries a non-null `tenant_id` and a `tenant_isolation`
policy keyed to a per-transaction session variable, the `probectl.tenant_id`
GUC ("Grand Unified Configuration" — Postgres's name for a runtime setting).
`tenancy.InTenant` (in `internal/tenancy/tenancy.go`) opens a transaction, runs
`SET LOCAL ROLE probectl_app`, sets that variable to the caller's tenant, and
only then runs the repository code. The effect: even a predicate-free
`SELECT * FROM incidents` returns only the caller's rows, because the policy
silently `AND`s `tenant_id = current_setting('probectl.tenant_id')` onto every
query. Picture a wristband at a venue: the transaction is banded with one
tenant at the door, and the database hands out only rows wearing the matching
band — no matter how broad the question asked upstairs was.

**Why it actually holds — the three things that make RLS more than a suggestion:**

- **The app role cannot bypass it.** `probectl_app` is created
  `NOSUPERUSER NOBYPASSRLS` (migration `0007_app_role.sql`). RLS in Postgres is
  ignored by superusers and by any role with the `BYPASSRLS` attribute — so if
  probectl connected as one of those, every policy would be decorative. It does
  not.
- **Even the table owner is bound.** Tenant tables use `FORCE ROW LEVEL SECURITY`,
  not just `ENABLE`. Plain `ENABLE` exempts the table's *owner* from its own
  policies — a subtle gap a security audit named. `FORCE` closes it.
- **A misconfigured deployment refuses to serve.** Before the control plane
  accepts traffic, `main` calls `tenancy.AssertIsolationPosture`
  (`internal/tenancy/posture.go`). Inside a real `probectl_app`-scoped
  transaction it checks that the effective role is non-super and non-bypass-RLS,
  and that **every** table with a `tenant_id` column has `FORCE` row security. If
  any check fails — RLS silently off, migrations not applied, the wrong role — it
  is a fatal startup error. The control plane will not start. The
  `cross-tenant-isolation` CI job proves this check passes on a correctly
  migrated database *and* rejects a deliberately unforced table, so the check is
  not a no-op.

**The provider plane is a separate, weaker role.** MSP operators (MSP — managed
service provider, the team running the platform for many customer tenants) run
as `probectl_provider` (also `NOBYPASSRLS`), granted only operational-metadata
tables (fleet, lifecycle) and **never** telemetry — see `tenancy.InProvider`. It
sets no tenant variable, so the per-tenant policies match nothing for it and only
the explicit provider grants apply. An operator literally cannot `SELECT` a
tenant's flows through this path.

## ClickHouse — high-volume telemetry (flow, path, threat, change, cost)

ClickHouse holds the firehose: flows, L7 events, threat signals. It gets a
layered defense because the pooled service account that ingests data is, by
necessity, powerful.

**Layer 1 — application scoping (always on).** Every tenant-scoped query leads
with `WHERE tenant_id = {tenant:String}`, and an unscoped call is refused in code
with `ErrNoTenant` (`internal/store/pathstore/clickhouse.go`). This is the
primary boundary in a default deployment.

**Layer 2 — values are server-bound, never string-concatenated.** Every value in
a ClickHouse query travels as a bound parameter: a `{name:Type}` placeholder in
the SQL plus a matching HTTP `param_name` that the **server** substitutes
(ClickHouse's native parameterized-query mechanism — not client-side escaping).
A tenant id shaped like `x' OR '1'='1` arrives as *data*, never as syntax, so it
cannot break out of the `WHERE` clause. The old hand-rolled escaping helpers were
deleted; the few things SQL cannot bind — table names, ClickHouse user names —
are validated against a strict regex and refused on mismatch. A CI gate
(`scripts/check_stringbuilt_sql.sh`, the `no-stringbuilt-sql` check) fails the
build if string-built ClickHouse SQL ever reappears.

**Layer 3 — a DB-level row policy for direct access.** A **row policy** is
ClickHouse's equivalent of RLS — a server-side row filter attached to the
table. `EnsureRowPolicies` installs a `probectl_tenant_isolation` policy
(`USING tenant_id = currentUser()`) so that an operator connecting with a
**per-tenant ClickHouse credential** (the siloed / direct-access convention;
see [../isolation.md](../isolation.md)) is constrained by ClickHouse itself and
cannot cross tenants — independent of probectl's code.

**The honest gap (and its opt-in fix).** probectl's own *pooled* deployment holds
**one** service credential, and that account is deliberately policy-exempt
(`probectl_service_access USING 1`) because it must insert, migrate, and run
admin counts across all tenants. So if Layer 1's `WHERE` scoping were ever
bypassed — a code bug, an injection that defeated Layer 2 — that single account
could read across tenants. Stated plainly so it is never a surprise.

The backstop, opt-in in `single` deployments and required in `multi-tenant` /
`regulated` ClickHouse deployments, removes that residual reach from the read
path entirely:

1. Every tenant-scoped **read** attaches a per-request custom setting,
   `SQL_probectl_tenant=<tenant>`. (Admin / cross-tenant reads — migrations,
   global counts — pass no setting, by design.)
2. A dedicated **reader user** (for example `PROBECTL_FLOWSTORE_READER_USER`;
   the same pattern exists for path, OTLP, and eBPF) gets
   `EnsureReaderRowPolicy`: a policy
   `probectl_reader_scope ... FOR SELECT USING tenant_id =
   getSetting('SQL_probectl_tenant')`, with no permissive escape. Because the
   reader user's setting **defaults to `''`** server-side, an unset or dropped
   setting matches **no rows** — **fail closed** (when the scope is missing,
   the answer is nothing, never everything).
3. Production routes tenant data reads through the reader user; the
   write/service user keeps full access for inserts and migrations only. A
   compromised query path that omits the `WHERE` still cannot cross tenants — the
   reader policy constrains it at the database.

Operator prerequisites (documented, not auto-configured): allow the custom
setting prefix (`<custom_settings_prefixes>SQL_</custom_settings_prefixes>`),
create the reader user with a default `SQL_probectl_tenant = ''`, and grant it
`SELECT` only. Under `PROBECTL_DEPLOYMENT_PROFILE=multi-tenant` or `regulated`,
the control plane refuses to start unless every ClickHouse-backed lane keeps
tenant scoping on and names its scoped reader user; the serve path then refuses
to start if row-policy installation fails. In the `single` profile, not enabling
this means Layer 1 is the boundary and the service account remains read-capable
across tenants.

**What the service/write account can still do (residual, by design):** insert
into any tenant's partition, run cross-tenant counts, and — without the reader
split — read across tenants. This is required for ingest, migrations, and
retention. It is bounded by three things: the application never issuing an
unscoped read, the secret-management of that one credential, and — when enabled —
the reader split taking it off the read path entirely.

## At-rest encryption of sensitive tenant values

Sensitive columns (alert-channel secrets, integration tokens, ...) are sealed
through `internal/tenantcrypto` — either the deployment-wide envelope key
(**envelope encryption**: the value is encrypted under a data key, and data
keys are themselves encrypted under one master key — so the master unlocks
keys, never data directly), or, on the licensed tier, a per-tenant keyring /
BYOK ("Bring Your Own Key" — the tenant's key lives in *their* secret manager;
see [../byok.md](../byok.md)). Keyless development runs pass the value through
in the clear, but the stored format is self-describing, so a sealed value can
never be silently misread as plaintext.

**Fail closed by default.** The serve path refuses keyless passthrough unless an
operator explicitly sets `PROBECTL_ALLOW_KEYLESS_DEV=true`. In other words:
without `PROBECTL_ENVELOPE_KEY`, `PROBECTL_ENVELOPE_KEY_FILE`, or the licensed
per-tenant keyring, the control plane fails closed rather than silently writing
tenant secrets in plaintext. The dev escape hatch is for throwaway local runs
only. (See [../hardening.md](../hardening.md) §0c.)

## How this is verified

These are the test suites that hold the claims above honest; most run on every CI
pass against real datastores.

- **`internal/tenancy` (`-tags isolation`):** the RLS posture check passes on a
  migrated DB and *rejects* an unforced table (non-vacuous — the suite proves
  the check can actually fail, so a green run means something); a cross-tenant
  query returns nothing. This is the standing `cross-tenant-isolation` CI gate.
- **`internal/store/flowstore`:** the read-path setting attach, the reader-policy
  DDL shape (no permissive escape), the empty-reader rejection; and
  (`-tags isolation`) a non-service ClickHouse reader issuing a
  **predicate-free** read sees only its own tenant's rows — proving the row
  policy, not the app `WHERE`, is what scopes it.
- **`internal/pipeline` (`-tags isolation`):** end-to-end ingest injection — a
  payload claiming another tenant is rejected and never lands in the victim's
  partition, against real ClickHouse and the RLS-scoped registry on real
  Postgres. Plus (no infra) siloed records route only to namespaced topics, with
  fail-closed construction.
- **`internal/otel/otlp` (`-tags isolation`):** an OTLP push authenticated as one
  tenant but naming another is rejected; the sink only ever sees the
  authenticated tenant.
- **`internal/config`:** the at-rest-required and ClickHouse-scoping knobs parse
  and default off.
