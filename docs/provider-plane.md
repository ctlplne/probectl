# Provider / management plane

This is the operator surface an **MSP** (a managed service provider — an
organization that self-hosts probectl once and resells it to many customer
tenants) or an internal platform team uses to run a
*multi-tenant* probectl: provisioning and suspending tenants, watching
fleet-wide health across all of them, and — under tight controls — reaching into
a single tenant's telemetry. It lives in **`ee/provider`** and activates only when
the license grants `provider_plane`. Without that license, `/provider/*` returns a
plain 404: the feature is *hidden*, not locked behind an upsell wall.

The single most important thing to understand: **a provider operator is a
different kind of user from a tenant user, in a different security domain, and
running a tenant gives an operator zero ability to read that tenant's data.**
The operator is the landlord: the master key opens the boiler room and the
breaker panel, never the tenants' filing cabinets. Everything below enforces
that line.

## The privilege model

Provider operators are not tenant users. They are a distinct **privilege
domain** — a self-contained authentication world with its own accounts,
sessions, and audit, whose credentials mean nothing in the tenant world (and
vice versa) — with their own everything:

- **Their own accounts** (`provider_operators`), **their own sessions** (a
  separate cookie, `probectl_provider_session`; `SameSite=Strict`, meaning the
  browser refuses to attach it to any navigation that starts on another site, so
  a malicious page cannot ride an operator's session; a 4-hour TTL,
  held in memory by design — a restart deliberately re-authenticates this
  high-privilege domain rather than persisting its sessions), and **their own
  tamper-evident audit chain** (`provider_audit_events`).
- **Multi-factor auth is mandatory** — there is no password-only login. Every
  sign-in is email + password (hashed with PBKDF2-HMAC-SHA256, per NIST SP
  800-132 — a deliberately *slow*, salted password hash, so a stolen database of
  hashes resists brute force) **plus** a TOTP code (RFC 6238, the standard
  authenticator-app
  6-digit code). TOTP secrets are envelope-sealed at rest — encrypted under the
  deployment's envelope key rather than stored readable — which is exactly why
  the provider plane refuses to even start without `PROBECTL_ENVELOPE_KEY`.
- **Separation of duties** — the principle that no single account both grants a
  power and wields it. Two roles: `admin` manages operators; `operator` runs
  tenant lifecycle and break-glass. An admin holds both. Disabling an operator
  revokes their live sessions immediately, not at the next TTL (**TTL** —
  time-to-live, the lifespan after which a session or grant self-expires).
- **No implicit read access to tenant telemetry — and this is enforced in the
  database, not just in handler code.** Every provider query runs as the
  `probectl_provider` Postgres role (via `tenancy.InProvider`). That role's only
  telemetry-adjacent grant is `SELECT` on `agents`, through an explicit
  `provider_fleet_read` policy (so the fleet view works). It has *no grant at
  all* on `tests`, `results`, or any other tenant table — so even a buggy or
  malicious handler physically cannot read tenant telemetry. The integration test
  `TestProviderRoleCannotReadTelemetry` proves the role is denied.

## Bootstrap → enrollment → login

How the very first operator comes into existence on a fresh deployment, and how
every operator after that enrolls:

1. **Bootstrap the first admin.** Set `PROBECTL_PROVIDER_BOOTSTRAP_TOKEN` on the
   deployment, then `POST /provider/v1/auth/bootstrap` with that token to create
   the first admin. It is single-use — the moment *any* operator exists, the
   bootstrap path goes inert, so the token cannot be replayed.
2. **Enroll.** Creating an operator (whether via bootstrap or by an existing
   admin) returns a **one-time enrollment token** — only its hash is stored. The
   operator exchanges it in two steps: `enroll/start` binds the authenticator (the
   TOTP secret travels exactly once, over TLS, and is sealed at rest), and
   `enroll/complete` verifies the first TOTP code, sets the password (minimum 12
   characters), and activates the account.
3. **Log in** with email + password + TOTP. Failures are deliberately *uniform* —
   nothing distinguishes a wrong password from a wrong code from an unknown email,
   so an attacker can't probe which part they got right.

## Tenant lifecycle

These are the actions an operator takes on tenants. Every one of them is recorded
on the provider audit stream with the acting operator's identity.

| Action | Effect |
|---|---|
| Provision | Creates the tenant (slug + name). The license's **tenant band** is enforced *here*: provisioning past the band fails loudly with `tenant_band_exhausted`, and existing tenants are never affected. (A suspended tenant still occupies a band slot; an offboarded one does not.) |
| Configure | Rename the tenant. |
| Suspend | The tenant's **users are rejected at the API** (`tenant_suspended`, via the core lifecycle gate in `requirePermission`). Data, agents, and ingestion are left untouched — suspend is a reversible billing/lifecycle state, never destruction. |
| Resume | Reactivates a suspended tenant. |
| Offboard | Marks the tenant `offboarding`: API access stops and the band slot frees. Offboarding **never silently destroys data** — the actual data export and verifiable deletion is a separate compliance flow (deliberately core/free). |

## Break-glass: the only path to tenant telemetry

Since operators have no standing access to tenant data, "break-glass" is the one,
narrow, heavily-controlled way in. The name is the fire-alarm cover: access
exists for genuine emergencies, but using it means visibly shattering the glass
— it cannot be done quietly, and everyone can see it was done. A grant is
**explicit, time-bounded,
tenant-consented, operator-bound, and audited on every single access**:

1. **An operator requests access** to a tenant: a reason (required) and a TTL
   (capped by `PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES`, default 4 hours).
   The grant starts in state `pending`.
2. **The tenant decides — not the operator.** A tenant admin (holding the
   `directory.write` permission) approves or denies it via the consent endpoints,
   authenticated by the **tenant** session, not an operator session. A tenant can
   only ever see and decide its *own* grants. This is the consent that makes the
   whole mechanism legitimate.
3. **Only an `active` grant unlocks the read** — meaning consented, unexpired, and
   unrevoked — and only for the operator who requested it. The surface today is
   the latest-results read model (`GET /provider/v1/breakglass/{id}/results`).
4. **Every access writes a provider audit record *before* the data is returned** —
   an access that cannot be audited is simply not allowed to happen. Revocation,
   denial, or expiry ends access immediately, and the grant's `use_count` shows
   exactly how many audited reads it carried.

## License degrade

The provider plane follows the same expiry ladder as the rest of the editions
system (see [`editions.md`](editions.md)). In short: `active` → full function;
`grace` (within 30 days past expiry) → full function, with the console bannering
the deadline; `read_only` (past grace) → **GETs keep working, but every mutation
returns `license_read_only`** (no new tenants, operators, or grants). Running
telemetry is never touched — expired is not the same as broken observability.

## The console

The console lives at `/provider` in the web app and is a **deliberately
visually-separate surface** — its own shell, a loud "PROVIDER PLANE — operator
domain, no tenant context" banner, no tenant indicator, and no entry in the
tenant navigation (it is marked `offNav` in the surface registry — the web
app's machine-checked list of every screen and where it is reachable). The separation
is intentional: an operator should never be able to confuse "I'm running the
platform" with "I'm inside a tenant." Its source lives in **`ee/web/provider`**
(the editions boundary applies to frontend code too — the `@ee` Vite alias,
pointing at `ee/web`, is the web seam). When the API returns 404 (unlicensed), the
console honestly renders "Provider plane not enabled." The screens: MFA login;
tenant inventory with lifecycle actions and a provision form; a
fleet-across-tenants table (counts and versions only — no telemetry);
break-glass request/list/revoke with per-grant audited-use counts; usage,
fairness, and governance cards (each documented on its own page —
[`metering.md`](metering.md), [`fairness.md`](fairness.md),
[`governance.md`](governance.md)); and, for admins, the white-label branding
card ([`white-label.md`](white-label.md)) and operator management with one-time
enrollment tokens.

## Engineering eval smoke

The provider journey has one deliberate precondition: a deployment must attach
the provider plane through the edition seam. A community or otherwise
unlicensed build must keep returning a plain 404 for `/provider/*`. Think of
that as the door not existing in that build, not as a locked door with a sales
message behind it.

For an engineering evaluation, use a disposable local stack and a provider-tier
eval license issued for that evaluation. Do not weaken `internal/license`, do
not make core import `ee/`, and do not use `PROBECTL_ALLOW_KEYLESS_DEV` for a
provider-plane smoke. The minimum runtime preconditions are:

- `PROBECTL_LICENSE_FILE` points at an offline-signed license whose feature set
  includes `provider_plane`.
- `PROBECTL_ENVELOPE_KEY` is set, because provider TOTP secrets are sealed at
  rest.
- `PROBECTL_PROVIDER_BOOTSTRAP_TOKEN` is set for the first operator bootstrap.
- The database migrations have run, including the provider tables and
  `probectl_provider` role grants.

The quick smoke has two halves:

```sh
GOCACHE=/private/tmp/probectl-gocache go test ./internal/control -run TestProviderPlaneMountSeam -count=1
GOCACHE=/private/tmp/probectl-gocache go test ./ee/provider -run 'TestProviderLifecycle|TestProviderOpenAPIMatchesRoutes' -count=1
cd web && npm test -- src/test/provider-console.test.tsx
```

The first command proves the hidden-unlicensed contract from core: without an
attached provider handler, `/provider/*` is indistinguishable from any unknown
route; with an attached handler, core dispatches without knowing any `ee/`
types. The second command proves the provider-enabled onboarding path:
bootstrap, MFA enrollment/login, tenant lifecycle, license-band enforcement,
audit records, and provider OpenAPI parity. The web command proves the console
renders both states: "Provider plane not enabled" when the API is hidden, and
the operator onboarding/lifecycle surfaces when the provider API is available.

## API

The provider API is `/provider/v1/*`, documented in `ee/provider/openapi.json`,
with a route-vs-spec parity self-test (`TestProviderOpenAPIMatchesRoutes`) that
mirrors the core OpenAPI gate — so the spec can't drift from the handlers. Core
mounts the whole surface as an **opaque `http.Handler`** via
`Server.WithProviderPlane`, handed in from the `attachEE` seam
(`cmd/probectl-control/ee_attach.go`, `//go:build !probectl_core`). Core never
imports the provider package directly; it only ever sees an `http.Handler` —
Go's standard "thing that answers HTTP requests" interface, so core forwards
requests without knowing any provider types exist — which
is what keeps the "core never imports `ee/`" rule intact.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_PROVIDER_BOOTSTRAP_TOKEN` | (none) | single-use first-admin bootstrap |
| `PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES` | `240` | break-glass TTL cap (5–1440) |
| `PROBECTL_ENVELOPE_KEY` | (none) | **required** for the provider plane (TOTP secrets are sealed at rest) |

Plus a provider-tier license (`PROBECTL_LICENSE_FILE`) granting
`provider_plane` — see [`editions.md`](editions.md).
