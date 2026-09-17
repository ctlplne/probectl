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
  a malicious page cannot ride an operator's session; a 4-hour absolute TTL
  plus the default-on `PROBECTL_SESSION_IDLE_TIMEOUT` inactivity wall,
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
   bootstrap path goes inert, so the token cannot be replayed. The database
   serializes the zero-operator check, first insert, and mandatory
   `provider.bootstrap` audit append in one provider-scoped transaction.
   Concurrent attempts and later retries lose with the same `409 conflict`;
   they create neither an operator nor a success audit.
2. **Enroll.** Creating an operator (whether via bootstrap or by an existing
   admin) returns a **one-time enrollment token** — only its hash is stored. The
   operator exchanges it in two steps: `enroll/start` binds the authenticator (the
   TOTP secret travels exactly once, over TLS, and is sealed at rest), and
   `enroll/complete` verifies the first TOTP code, sets the password (minimum 12
   characters), and activates the account.
3. **Log in** with email + password + TOTP. Failures are deliberately *uniform* —
   nothing distinguishes a wrong password from a wrong code from an unknown email,
   so an attacker can't probe which part they got right. The session that comes
   back is **persisted in Postgres** (`provider_sessions`, keyed token hash only,
   4-hour lifetime, idle timeout), so every control replica behind the ingress
   honours it and a logout, an idle expiry, or disabling the operator ends it on
   all replicas at once (DPR-033).

The same flow has named CLI paths: `probectl provider bootstrap`,
`enroll-start`, `enroll-complete`, and `login`. These four requests contain
credentials, so the CLI deliberately refuses inline `--body`. Supply the one
JSON object through stdin (`--body-file -`) or a real, non-symlinked mode-`0600`
file (`--body-file /owner-only/path.json`). The login response includes the
provider bearer token used by later `probectl provider ...`, `tenant ...`, and
`billing ...` commands; inject it with `PROBECTL_API_TOKEN`, not the global
`--token` argument, so it does not enter the process list or shell history.
`logout`, `provisioning`, and `abandon-provision` are named commands too.

## Tenant lifecycle

These are the actions an operator takes on tenants. Every one of them is recorded
on the provider audit stream with the acting operator's identity.

| Action | Effect |
|---|---|
| Provision | Creates the tenant (slug + name). Pooled tenants publish atomically. A siloed/hybrid tenant first appears in the provider inventory as **`provisioning`**, outside the routable tenant registry, while its isolated stores are created. A failed attempt stays non-routable and does not consume the tenant band; posting the same slug, name, model, and residency resumes the same tenant ID. Only the atomic `active` publication consumes the license's **tenant band**, and that final transition rechecks the band under a database lock. Provisioning past the band fails loudly with `tenant_band_exhausted`; a suspended tenant still occupies a slot and an offboarded one does not. Attempt, failure category, and completion are separately recorded on the provider audit stream. |
| Configure | Rename the tenant. |
| (on publication) | Every tenant is published **with its system roles** — `admin` (every permission), `editor` (reads plus test/alert/incident writes) and `viewer` (reads) — so the first administrator can be granted immediately with `probectl-control bootstrap-admin -tenant <uuid> -email …` or through SCIM group mapping (DPR-035). Seeding is idempotent and `bootstrap-admin` repeats it, so tenants created before this rule are healed on their first grant. |
| (after publication) | Install the tenant's IR public key (`probectl audit ir-keygen <uuid>` offline, then `probectl-control ir-key-install <uuid>` on the control plane) so break-glass into it can be requested; until then a request is refused with `409 ir_key_unavailable` (DPR-036, [`audit.md`](audit.md)). |
| Suspend | The tenant's **users are rejected at the API** (`tenant_suspended`, via the core lifecycle gate in `requirePermission`). Data, agents, and ingestion are left untouched — suspend is a reversible billing/lifecycle state, never destruction. |
| Resume | Reactivates a suspended tenant. |
| Offboard | Marks the tenant `offboarding`: API access stops and the band slot frees. Offboarding **never silently destroys data** — the actual data export and verifiable deletion is a separate compliance flow (deliberately core/free). |

Provisioning failure audit data is deliberately bounded and phase-aware:
`silo_provision_failed` means an isolated datastore leg failed before registry
publication; `registry_publish_failed` means the final atomic publication failed.
Cancellation, deadline, and tenant-band failures use `canceled`,
`deadline_exceeded`, and `tenant_band_exhausted`. Raw backend error text is never
copied into the provider audit stream.

## Break-glass: the only path to tenant telemetry

Since operators have no standing access to tenant data, "break-glass" is the one,
narrow, heavily-controlled way in. The name is the fire-alarm cover: access
exists for genuine emergencies, but using it means visibly shattering the glass
— it cannot be done quietly, and everyone can see it was done. A grant is
**explicit, time-bounded,
tenant-consented, operator-bound, and audited on every single access**:

1. **An operator requests access** to a tenant: a reason (required) and a TTL
   (capped by `PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES`, default 4 hours).
   The grant starts in state `pending`. The tenant's IR public key must
   already be in the keyring (`probectl audit ir-keygen` then
   `probectl-control ir-key-install`, see [`audit.md`](audit.md)); otherwise
   the request is refused with `409 ir_key_unavailable`, the response says
   exactly which file and commands are missing, and nothing is recorded.
2. **The tenant decides — not the operator.** A tenant admin (holding the
   `directory.write` permission) approves or denies it via the consent endpoints,
   authenticated by the **tenant** session, not an operator session. The consent
   check resolves the tenant first, then requires that RBAC permission, then
   applies the tenant's ABAC deny policies to the user's current subject
   attributes. A policy/attribute-store failure denies the decision rather than
   treating it as an empty policy set. A tenant can only ever see and decide its
   *own* grants. This is the consent that makes the whole mechanism legitimate.
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

## MSP consumption and export

The MSP tier uses the existing local usage meters (`agents`, `tests`,
`results_ingested`, `ingest_bytes`, `flow_events`, and `ai_calls`) as its
consumption basis. The path is deliberately one-way and operator-driven:

1. tenant-scoped streams update meters inside this self-hosted deployment;
2. an authenticated provider operator requests
   `GET /provider/v1/usage/export?format=csv|jsonl`;
3. the operator sends that file through the commercial process agreed with
   probectl and may independently map the same data into its own customer
   pricing.

There is no background uploader, billing beacon, vendor callback, or implicit
telemetry read. If the operator does not run an export, nothing leaves the
deployment. See [`metering.md`](metering.md) for meter semantics and the stable
export columns.

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
[`governance.md`](governance.md)); and operator management with one-time
enrollment tokens for admins. MSPs resell the service under the probectl banner.

## Engineering eval smoke

The provider journey has one deliberate precondition: a deployment must attach
the provider plane through the edition seam. A community or otherwise
unlicensed build must keep returning a plain 404 for `/provider/*`. Think of
that as the door not existing in that build, not as a locked door with a sales
message behind it.

For an engineering evaluation, use a disposable local stack and an MSP-tier
eval license issued for that evaluation. Do not weaken `internal/license`, do
not make core import `ee/`, and do not use `PROBECTL_ALLOW_KEYLESS_DEV` for a
provider-plane smoke. The minimum runtime preconditions are:

- `PROBECTL_LICENSE_FILE` points at an offline-signed license whose feature set
  includes `provider_plane`.
- `PROBECTL_ENVELOPE_KEY` is set, because provider TOTP secrets are sealed at
  rest.
- `PROBECTL_PROVIDER_BOOTSTRAP_TOKEN` is set for the first operator bootstrap.
- `PROBECTL_AUDIT_WORM_DIR` points at a durable absolute directory: the plane
  refuses admission until provider/break-glass audit rows have a signed WORM
  export (the signing key is generated at `PROBECTL_WORM_SIGNING_KEY_FILE` on
  first start unless `PROBECTL_WORM_SIGNING_KEY` is injected).
- `PROBECTL_IR_PUBLIC_KEY_DIR` points at the operator-owned IR public keyring
  (absolute path; created empty on first start). Break-glass attribution is
  sealed to `<tenant-uuid>.pem` in that directory, and a grant for a tenant
  whose key is absent is refused with `409 ir_key_unavailable` until the key
  exists. Mint the pair with `probectl audit ir-keygen <tenant-id>` and
  install the public half with `probectl-control ir-key-install <tenant-id>`
  (it reads stdin, so it works through `kubectl exec -i` on the shell-less
  image) — see [`audit.md`](audit.md).
- The database migrations have run, including the provider tables and
  `probectl_provider` role grants.

The shipped deploys wire the last two for you: Compose with
`deploy/compose/provider.yml` layered over `probectl.yml` + `license.yml`
(evaluation-grade, on the persistent volume), and the Helm multitenant profile
(`values-multitenant.yaml`, on the shared object-lock mount). A missing setting
is reported by name at startup instead of a crash loop.

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

Plus an MSP-tier license (`PROBECTL_LICENSE_FILE`) granting
`provider_plane` — see [`editions.md`](editions.md).
