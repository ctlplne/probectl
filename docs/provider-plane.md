# Provider / management plane (S-T1)

The operator surface an MSP (or internal platform team) uses to run a
multi-tenant probectl: tenant lifecycle, fleet-across-tenants health, and
audited break-glass. It lives in **`ee/provider`** and activates only when the
license grants `provider_plane` (MSP bands) — unlicensed deployments serve a
plain 404 on `/provider/*` (hidden, not locked).

## The privilege model

Provider **operators are not tenant users**. They form a distinct privilege
domain (CLAUDE.md §7 guardrail 1):

- Their own accounts (`provider_operators`), their own sessions (a separate
  cookie, `probectl_provider_session`, SameSite=Strict, 4h TTL, in-memory by
  design — a restart re-authenticates a high-privilege domain), and their own
  tamper-evident audit chain (`provider_audit_events`).
- **MFA is mandatory.** There is no password-only login: every sign-in is
  email + password (PBKDF2-SHA256, SP 800-132) + a TOTP code (RFC 6238).
  TOTP secrets are **envelope-sealed at rest**, which is why the provider
  plane refuses to build without `PROBECTL_ENVELOPE_KEY`.
- **Separation of duties**: `admin` manages operators; `operator` runs tenant
  lifecycle and break-glass. Admins hold both. Disabling an operator revokes
  their live sessions immediately.
- **No implicit read access to tenant telemetry — enforced at the storage
  layer.** Every provider query runs as the `probectl_provider` Postgres role
  (`tenancy.InProvider`), whose only telemetry-adjacent grant is SELECT over
  `agents` via the explicit `provider_fleet_read` policy. It has no grant at
  all on `tests`, `results`, or any other tenant table: even a buggy handler
  cannot read them. The integration suite proves it
  (`TestProviderRoleCannotReadTelemetry`).

## Bootstrap → enrollment → login

1. Set `PROBECTL_PROVIDER_BOOTSTRAP_TOKEN` on the deployment. `POST
   /provider/v1/auth/bootstrap` with that token creates the **first admin**;
   it is single-use — inert the moment any operator exists.
2. Creating an operator (bootstrap or admin) returns a **one-time enrollment
   token** (only its hash is stored). The operator exchanges it:
   `enroll/start` binds the authenticator (the TOTP secret travels exactly
   once, over TLS, and is sealed at rest); `enroll/complete` verifies the
   first code, sets the password (min 12 chars), and activates the account.
3. Login is email + password + TOTP. Failures are uniform — no signal
   distinguishes a wrong password from a wrong code or an unknown email.

## Tenant lifecycle

| Action | Effect |
|---|---|
| Provision | Creates the tenant (slug + name). The license's **tenant band** is enforced here: provisioning beyond the band fails loudly (`tenant_band_exhausted`); existing tenants are never affected. Suspended tenants still occupy a band slot; offboarded ones do not. |
| Configure | Rename. |
| Suspend | The tenant's **users are rejected at the API** (`tenant_suspended`, via the core lifecycle gate in `requirePermission`). Data, agents, and ingestion are untouched — suspension is a reversible billing/lifecycle state, never destruction. |
| Resume | Reactivates. |
| Offboard | Marks `offboarding`: API access stops, the band slot frees. **Data export + verifiable deletion are S-T5** (a compliance right, deliberately core) — offboarding never silently destroys data. |

Every action lands on the provider audit stream with the acting operator.

## Break-glass: the only path to tenant telemetry

A grant is **explicit, time-bounded, tenant-consented, operator-bound, and
audited per access**:

1. An operator requests access: tenant + reason (required) + TTL (capped by
   `PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES`, default 4h). State:
   `pending`.
2. **The tenant decides.** A tenant admin (holding `directory.write`)
   approves or denies via the consent endpoints — authenticated by the
   TENANT session, not an operator session. A tenant can only ever see and
   decide its own grants.
3. Only an `active` grant (consented + unexpired + unrevoked) unlocks the
   telemetry read — and only for the operator who requested it. S-T1's
   surface is the latest-results read model
   (`GET /provider/v1/breakglass/{id}/results`).
4. **Every access writes a provider audit record before data is returned** —
   an unauditable access is no access. Revocation/denial/expiry end access
   immediately; the grant's `use_count` shows exactly how many audited reads
   rode it.

## License degrade (the S-T0 ladder)

`active` → full function. `grace` (≤30 days past expiry) → full function, the
console banners the deadline. `read_only` → **GETs keep working, every
mutation returns `license_read_only`** (no new tenants/operators/grants);
running telemetry is never touched. Expired ≠ broken observability.

## The console

`/provider` in the web app — a **visually-separate surface**: its own shell,
a loud "PROVIDER PLANE — operator domain, no tenant context" banner, no
tenant indicator, and no entry in the tenant nav (`offNav` in the surface
registry). Source lives in **`ee/web/provider`** (the editions boundary
applies to frontend code too; the `@ee` Vite alias is the web seam). When the
API 404s (unlicensed), the console renders "Provider plane not enabled"
honestly. Screens: MFA login, tenant inventory + lifecycle actions +
provision form, fleet-across-tenants table (counts/versions only),
break-glass request/list/revoke with per-grant audited-use counts, and (for
admins) operator management with one-time enrollment tokens.

## API

`/provider/v1/*` — documented in `ee/provider/openapi.json`, with a route↔spec
parity self-test (`TestProviderOpenAPIMatchesRoutes`) mirroring the core
OpenAPI gate. The surface is mounted by core as an opaque `http.Handler`
(`Server.WithProviderPlane`) from the `attachEE` seam
(`cmd/probectl-control/ee_attach.go`, `//go:build !probectl_core`).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_PROVIDER_BOOTSTRAP_TOKEN` | (none) | single-use first-admin bootstrap |
| `PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES` | `240` | break-glass TTL cap (5–1440) |
| `PROBECTL_ENVELOPE_KEY` | (none) | **required** for the provider plane (TOTP secrets are sealed at rest) |

Plus a provider-tier license (`PROBECTL_LICENSE_FILE`) granting
`provider_plane` — see `docs/editions.md`.
