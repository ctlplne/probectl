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

Session, MCP, SCIM, OTLP, and agent-enrollment authentication must first turn
an unguessable token hash into a tenant. Siloed tenants make this a two-step
operation: a forced-RLS `public.credential_locators` row holds only the
credential kind, detailed-row UUID, opaque hash, tenant UUID, and inactive
timestamps; after that exact hash resolves, `tenancy.InTenant` selects the
tenant's physical schema and reads or touches the detailed row there. Email,
display name, MFA, preferences, user identity, and credential labels never move
to the global locator. Pooled tenants use the identical path, with their detail
table in `public`.

Direct `probectl_app` access still matches zero locator or detail rows without
the tenant GUC. Locator register/resolve/consume/rotation goes through narrowly
shaped `SECURITY DEFINER` functions owned by the non-login,
`NOBYPASSRLS` `probectl_pretenant_auth` role. The role has no general runtime
entry point, and the application receives only `EXECUTE` on those functions.
An authenticated-login replacement locks and tombstones the predecessor's
global locator, so concurrent callbacks still produce at most one successor
even when predecessor and successor detail rows live in different silos.

Deployment-wide certificate denial uses the same split:
`agent_identity_revocations` contains only the serial/SPIFFE revocation metadata
needed before a tenant transaction exists; full issuance history remains in the
tenant schema. Existing silos are backfilled by migration 0073 and by silo
CatchUp. Deployment-wide deny-list reads remain a separate provider operation,
executable only after `tenancy.InProvider` assumes `probectl_provider`.

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
  that **every** table with a `tenant_id` column has `FORCE` row security, and
  that the pre-tenant auth/provider tables have exactly one strict application
  policy rather than an unset-GUC allowance. If any check fails — RLS silently
  off, permissive policy semantics, migrations not applied, the wrong role — it
  is a fatal startup error. The control plane will not start. The
  `cross-tenant-isolation` CI job proves this check passes on a correctly
  migrated database *and* rejects a deliberately unforced table, so the check is
  not a no-op.

**The provider plane is a separate, weaker role.** MSP operators (MSP — managed
service provider, the team running the platform for many customer tenants) run
as `probectl_provider` (also `NOBYPASSRLS`), granted only operational-metadata
tables (fleet, lifecycle) and **never** telemetry — see `tenancy.InProvider`. It
sets no tenant variable, so the per-tenant policies match nothing for it and only
the explicit provider grants and role-specific policies apply. Break-glass grant
metadata uses one such provider-only policy; it is never opened by an unset
tenant GUC. An operator literally cannot `SELECT` a tenant's flows through this
path.

## ClickHouse — high-volume telemetry (flow, path, endpoint, threat, change, cost)

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

Setting-scoped runtime reader policies are converged in two steps,
`CREATE ROW POLICY IF NOT EXISTS …` and then `ALTER ROW POLICY …`, at every
boot and on every per-tenant table (DPR-325). The `ALTER` matters: when a
reader credential rotates, the fixed policy name must move its `TO` binding to
the new validated user; `IF NOT EXISTS` alone would leave the new reader
without the intended filter. The policy is never replaced: ClickHouse runs
`CREATE ROW POLICY OR REPLACE` as remove-then-insert, and a reader query that
started in between found no policy and read every row (measured on the pinned
24.8 image: 291 of 17,685 concurrent foreign-tenant reads unfiltered while one
replica re-applied the policy; zero with create-then-alter). That is like
changing a lock by taking the old one out first: for a moment the door is
open. The real-ClickHouse proof is
`TestReaderRowPolicyReapplyNeverOpensTheTable` (`internal/store/chclient`,
`-tags isolation`).

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
   the same pattern exists for path, OTLP, eBPF, and endpoint/DEM events) gets
   `EnsureReaderRowPolicy`: a policy
   `probectl_reader_scope ... FOR SELECT USING tenant_id =
   getSetting('SQL_probectl_tenant')`, with no permissive escape. Because the
   reader user's setting **defaults to `''`** server-side, an unset or dropped
   setting matches **no rows** — **fail closed** (when the scope is missing,
   the answer is nothing, never everything).
3. Every tenant-scoped **read** — queries, tenant exports and DSAR subject
   exports, of the pooled tables and (DPR-323) of a siloed or hybrid tenant's
   own database — is sent **as the reader user**, over its own connection
   authenticated with the reader's credential
   (`PROBECTL_CLICKHOUSE_READER_BASIC_AUTH_FILE`; DPR-285). The write/service
   (control) login keeps inserts, migrations, row-policy DDL, retention TTLs and
   erasure, with erasure's verification counts, so a policy can never hide
   surviving rows from a deletion attestation. A query path that omits the
   `WHERE` still cannot cross tenants: ClickHouse returns only the rows the
   reader policy admits. With scoping on and no reader credential, the read
   fails; it never falls back to the control login.
4. At boot, the control plane proves the reader against the live server and
   refuses to start otherwise: the credential authenticates as the configured
   `*_READER_USER`, is not the control login, resolves the control login's
   default database, is refused `INSERT` and `CREATE` (`ACCESS_DENIED`), holds
   no grant broader than the proof can vouch for (DPR-328: its own
   `SHOW GRANTS` may list only `SELECT` on its default database and `SELECT` on
   individual tables; a global or other database-wide grant, any other
   privilege, a grant option, a role or a partial revoke is refused, because
   such a reader would read, unfiltered, any table created after the proof
   ran), and, on every policy table that holds rows, sees none of them under a
   tenant that owns none (so the policy really binds it).

Before DPR-285 step 3 was not true: the control plane sent every read as its
single control login, the policy bound a reader user it never logged in as,
and ClickHouse's default `users_without_row_policies_can_read_rows=true` let the
control login read every row. The `WHERE` clause was the only thing scoping
reads, whatever the profile said.

**Per-tenant databases (siloed/hybrid, DPR-323).** A siloed or hybrid tenant's
telemetry lives in its own ClickHouse database, optionally on a residency data
plane. Until DPR-323 those reads ran as the control login, on the argument that
the database holds only one tenant's rows. That made the database *name* the
whole boundary: a routing bug that sent tenant X's read to tenant Y's database,
together with a read that lost its `WHERE`, would have served Y's rows. Now:

- the silo provisioner (`ee/silo`) installs the same setting-scoped policy,
  `probectl_reader_scope … USING tenant_id = getSetting('SQL_probectl_tenant')
  TO <reader>`, on **every** table of the per-tenant database and only then
  grants the reader `SELECT` on that table — policy first, grant second, one
  table at a time, never `db.*`, never a view. A table created later is
  unreadable by the reader until it is scoped too; a data table without a
  `tenant_id` column is refused, never granted;
- the read goes to the reader lane (`chclient.RouteRead`) with the tenant
  setting, on the tenant's residency plane when it has one, using the reader's
  credential pinned to that plane's origin
  (`PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES`);
- the proof runs when the silo is provisioned (before the call returns) and
  again at **every boot for every siloed and hybrid tenant, before the silo
  router is published**: on each plane the reader authenticates as the
  configured reader user and is not the control login, is refused `INSERT`
  and `CREATE`, and on every per-tenant table that holds rows sees none of them
  under a tenant setting that owns none. A scope that cannot be proven is
  withdrawn (its grants revoked), and startup is refused;
- teardown revokes the reader's grants (before the database is dropped) and
  drops the policies.

**What the setting-scoped policy contains, and what it does not.** It
contains a *lost or misrouted query*: a read that dropped its `WHERE`, or that
the router sent to the wrong tenant's database, still carries the
authenticated tenant's `SQL_probectl_tenant`, so ClickHouse returns only that
tenant's rows. It is not a boundary against *injected SQL*. The reader is not
`readonly`, so SQL text that ends in `SETTINGS SQL_probectl_tenant='<other>'`
overrides the request's setting, and since DPR-323 the reader also sees every
per-tenant database's *name* in `system.databases` (names only: the tables
stay behind their policies). Neither is reachable from a request: the store
appends the tenant setting itself from the authenticated tenant, every value
is a server-bound `param_*`, and no request input can name a ClickHouse
setting or add SQL text. Injection is held off by those, not by the policy.

**Stores on different ClickHouse servers.** Each tenant-scoped store's reader
client sends the reader's credential only to that store's own origin and to
the planes pinned in `PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES`. A residency
plane that shares one store's origin but not another's is therefore reachable
by the first store's reader only; the boot catch-up and provisioning check
each scoped store and, for a plane that hosts a tenant, refuse naming the
store whose reader cannot reach it (`Config.DataPlaneReaderGap`, DPR-327).
List such a plane in `PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES`.

Granting the reader its per-tenant tables needs the control login to hold
`SELECT ON *.* WITH GRANT OPTION` on each ClickHouse server that hosts silos
(the default plane and every residency plane); without it provisioning and the
boot catch-up fail closed with that instruction. Grants name the reader user;
when you **rename** the reader (not just rotate its password), drop the old
user, because the replaced policies no longer bind it and its old per-table
grants would let it read unfiltered.

Operator prerequisites (documented, not auto-configured): allow the custom
setting prefix (`<custom_settings_prefixes>SQL_</custom_settings_prefixes>`),
create the reader user with a default `SQL_probectl_tenant = ''`, grant it
`SELECT` on the control login's default database only, and give the control
plane its credential file. With siloed/hybrid tenants, also give the control
login `SELECT ON *.* WITH GRANT OPTION` (so it can grant the reader each
per-tenant table) and, on every residency plane, create the same reader user
and stage its credential in `PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES`. Under `PROBECTL_DEPLOYMENT_PROFILE=multi-tenant` or
`regulated`, the control plane refuses to start unless every ClickHouse-backed
lane keeps tenant scoping on, names its scoped reader user and has the reader
credential; the serve path then refuses to start if row-policy installation or
the reader proof fails. In the `single` profile, not enabling
this means Layer 1 is the boundary and the service account remains read-capable
across tenants.

**What the service/write account can still do (residual, by design):** insert
into any tenant's partition, run cross-tenant counts (erasure verification,
part pressure), and — without the reader split, that is with tenant scoping
off — read across tenants. This is required for ingest, migrations, and
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
- **`ee/silo` (`-tags integration` and `-tags isolation`,
  `TestSiloReaderLaneEnforcesTenantIsolationAtTheDB`):** two siloed tenants on
  a live Postgres and ClickHouse, one on a residency plane reached with
  origin-pinned credentials; a predicate-free read as the reader under X's
  setting against Y's database counts zero rows, a routed read misdirected to
  Y's database returns X nothing, a later table is refused to the reader until
  scoped, and teardown revokes every grant. Skipping the row policy turns it
  red (DPR-323).
- **`internal/store/pathstore` (`-tags isolation`,
  `TestPathSiloReadOfAnotherTenantsDatabaseFindsNothing`):** the store's own
  tenant read path, misrouted to another tenant's database with no `WHERE`,
  finds nothing; the same read as the control login finds the rows.
- **`internal/store/endpointstore`:** the first migration puts `tenant_id`
  first in both partition and order keys; restart reads require a non-empty
  tenant and use a server-bound tenant predicate plus the setting-scoped row
  policy. Unit and real-ClickHouse tests seed a decoy tenant and prove it is not
  returned.
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
