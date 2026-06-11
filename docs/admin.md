# Administering probectl

Day-2 operation of an installed deployment: identity and roles, the audit trail,
SSO, and the fleet of **agents** that actually feed the control plane. For
installation see [install.md](install.md); for every config key see
[configuration.md](configuration.md).

> **Consumer vs. producer.** The control plane is a *consumer* — it stores,
> correlates, and serves, but it observes nothing on its own. The **agents and
> collectors** are the *producers* that watch the network and ship what they see.
> A control plane with no producers is a healthy, empty database. So "operating
> the fleet" — enrolling, revoking, rotating, and upgrading agents — *is* a core
> day-2 job, covered in [Operating the agent fleet](#operating-the-agent-fleet-day-2)
> below. To stand up your first producer end-to-end, start with the
> [getting-started guide](getting-started.md); for the full catalog of producers
> and how to deploy each, see [deploying-agents.md](deploying-agents.md).

## Identity, roles, and access (RBAC)

probectl enforces a **two-level boundary** on every API path: the request first
resolves to exactly one tenant (one isolated customer/organization in the
deployment), then RBAC — role-based access control, the caller's permission set
— decides whether the caller may perform
that route's action. Tenant first, permissions second, always in that order: a
permission can never widen a request beyond its tenant. Authentication is
**OIDC SSO** (`PROBECTL_AUTH_MODE=session`) — SSO is single sign-on through
your existing identity provider (IdP: Okta, Entra ID, Keycloak, …), and OIDC
(OpenID Connect) is the standard protocol it speaks — so probectl never stores
or even sees a user password. The `dev` mode grants every request all access
with no authentication and is for local evaluation only — release binaries do
not even contain it (setting it makes the control plane refuse to start; see
[getting-started.md](getting-started.md) for the fenced evaluation path).

Seeded system roles (one set per tenant):

| Role     | Capability |
| -------- | ---------- |
| `admin`  | Full access within the tenant, including reading/exporting the audit trail. |
| `editor` | Read everything; manage tests, alerts, and incidents. |
| `viewer` | Read-only across the planes (no audit access). |

A **new SSO user is created with no roles** (the secure default) and is denied
scoped resources until an admin grants one. Inspect your own effective access at
`GET /v1/me`. Role bindings live in the `role_bindings` table. Users and roles
within a tenant are provisioned by your IdP over **SCIM 2.0** — the standard
user-provisioning protocol, where the IdP *pushes* user create/update/delete to
probectl instead of probectl polling the IdP (the `/scim/v2/...`
endpoints, authenticated by a per-tenant SCIM bearer token — a secret string
presented in the `Authorization` header; whoever holds it bears the access);
deprovisioning a user revokes their access.

## The audit trail

Every configuration change (creating, updating, or deleting a test, agent,
alert, or incident) and every authentication (the `auth.login` action) is
written to an **immutable, hash-chained, tamper-evident** audit log — in the
*same database transaction* as the action it records (so an action and its
audit record commit together or not at all — there is no window where one
exists without the other), and scoped to the tenant by
RLS (row-level security — the Postgres feature where the database itself
filters every row by tenant, beneath the application code). Provider-plane and
break-glass actions go to a **separate** provider audit
stream.

**Hash-chained** means each record carries a hash of the record before it —
like a chain where every link is engraved with the previous link's serial
number: remove, alter, or reorder one link and every engraving after it stops
matching. That is what makes the log tamper-*evident* rather than merely
append-only.

Read and verify it (requires the `audit.read` permission — `admin` by default):

```sh
# A page of the tenant's audit trail; the newest cursor is returned as "next".
curl --cacert ca.crt "https://HOST/v1/audit?after=0&limit=100"

# Verify chain integrity (returns ok=false with a detail if any record was altered).
curl --cacert ca.crt "https://HOST/v1/audit/verify"
```

Each event carries `seq`, `actor`, `action`, `target`, an optional `data`
object, and the `prev_hash` / `hash` chain links. Re-computing the chain detects
any insertion, deletion, reordering, or tampering — that's what `/v1/audit/verify`
does.

### Exporting to a SIEM

The audit log is built for export. `GET /v1/audit?after=<cursor>` is a pull
cursor: advance `after` to the last `seq` you've consumed. For programmatic
delivery, the engine exposes the `audit.Sink` hook plus `audit.Drain` (read a
page → deliver it → advance the cursor) — the stable contract the SIEM
connectors build on. (A SIEM — security information and event management — is
the SOC's central log-collection and alerting system.) probectl ships
connectors for **syslog, CEF, ECS, and OTLP** — respectively the classic Unix
log-line format, ArcSight's Common Event Format, the Elastic Common Schema, and
the OpenTelemetry protocol
(select the wire format with `PROBECTL_SIEM_FORMAT`). The `audit.export`
permission gates streaming export.

## SSO (OIDC)

Configure a single IdP per deployment with `PROBECTL_OIDC_ISSUER`,
`PROBECTL_OIDC_CLIENT_ID`, `PROBECTL_OIDC_CLIENT_SECRET`, and
`PROBECTL_OIDC_REDIRECT_URL` (`https://HOST/auth/callback`). Register that
callback with your IdP. Login begins at `GET /auth/login`; the session cookie is
`Secure + HttpOnly + SameSite=Lax` — sent only over HTTPS, unreadable to page
scripts, and not attached to cross-site requests — with lifetime
`PROBECTL_SESSION_TTL`
(default 12 h). Per-tenant IdPs (a tenant bringing its own SSO) resolve through a
provider factory; the factory exists today, but DB-backed per-tenant IdP
configuration is still to come — until it lands, the single env-configured IdP is
shared across tenants.

## Operating the agent fleet (day-2)

Agents are the producers; the control plane is the consumer. Keeping the fleet
healthy is the other half of day-2. The lifecycle has four operator touchpoints:
**enroll** an agent (give it an identity), **revoke** one that's compromised,
let the runtime **rotate** identities forever after, and **roll out** new
versions in waves. Each is detailed below; the deep walkthrough with the threat
model lives in [agent/enrollment.md](agent/enrollment.md).

The one idea underneath all of it: an agent is useless until it holds an
**SVID** — a short-lived mTLS client certificate whose identity names *both* its
tenant and its agent id (mTLS is mutual TLS: not only does the agent verify the
server, the server demands and verifies the agent's certificate too). No SVID,
no transport: the control plane refuses the
connection at the TLS handshake, so nothing the agent sends lands anywhere. You
never hand-copy certificates around; agents *earn* an identity by redeeming a
one-time token, and the runtime keeps it fresh on its own. The whole lifecycle
behaves like a hotel keycard system: a card that expires every 24 hours, a
runtime that re-issues it before checkout, and a front desk that can put any
card — or any *guest* — on the deny-list instantly.

### Enrolling an agent

Two steps, on two different hosts.

**1. Mint a join token on the control host.** This is an operator action; the
mint is audited and only a *hash* of the token is stored.

```sh
probectl-control enroll-token -tenant <tenant-uuid> [-agent <id>] [-name <label>] [-ttl 1h]
```

It prints — **once** — a single-use `pjt_…` token (default validity 1 hour), a
**token id** for your records, and the server-certificate **pin** (a hex SHA-256
of the control plane's serving cert) that the agent can use to trust the server
on first contact. The token is **tenant-scoped: the token, not the agent, names
the tenant**, which is why `-tenant` is required. `-agent` optionally nails the
token to one specific agent id; `-name` is a human label; `-ttl` shortens or
lengthens the window.

> The same mint is available over the admin API
> (`POST /v1/agents/enroll-tokens`, requires the `agent.write` permission) for
> automated provisioning — both surfaces go through the identical service path.

**2. Redeem the token on the agent host.** The agent generates its private key
**locally** (the key never leaves that host), sends a certificate request, and
receives its SVID, the issuing intermediate, and the trust bundle — all written
`0600` into `--dir`:

```sh
probectl-agent enroll \
  --server https://<control-host>:8443 \
  --token pjt_... \
  --dir /var/lib/probectl-agent/identity \
  --ca-pin <hex-sha256>          # the pin printed at mint, for self-signed deployments
  # …or, for a CA-issued control-plane cert:
  # --ca-file ca.crt
```

You must give the agent exactly one way to trust the server: `--ca-pin` (the pin
from step 1 — there is **no** trust-on-first-use fallback, so a mismatched pin
**refuses** the connection) or `--ca-file` (a CA bundle). On success it prints
the SVID's identity and expiry and the config snippet to point the agent at its
new identity files. Setting `identity.server` in that config is what enables the
automatic rotation described next.

### Revoking a compromised agent

If an agent (or its key) is compromised, revoke it:

```sh
probectl-control revoke-agent -tenant <uuid> -agent <id>
```

(A leaked join token that nobody has redeemed yet is the smaller case — void
the invitation itself with `probectl-control revoke-enroll-token -id
<token-id>`; the id prints at mint time, and single-use + the ~1h expiry
already bound the exposure.)

This **persists** the revocation (so it survives a control-plane restart) and
feeds the mTLS handshake **deny-list**. A *running* control plane reloads that
persisted list every **30 seconds**, so from its next connection the agent's
handshakes are refused, its live certificate serials are denied, and its
identity is denied outright — meaning even a re-issued certificate is rejected,
and both **enrollment and rotation refuse that identity** going forward. There
is no resurrection path short of an operator un-revoking it in the database.
(The admin API equivalent, `POST /v1/agents/{id}/revoke`, pushes the denial
**live immediately** rather than waiting for the 30-second refresh.)

### Certificate rotation — and what you watch

SVIDs are deliberately short-lived (24 hours), so a stolen one is only useful
briefly. With `identity.server` set, the agent runtime rotates **automatically
at roughly 2/3 of the certificate's lifetime**: it generates a fresh key, proves
possession of the current one, and asks the control plane to re-issue. The
**identity can never change on rotation** — only the key and expiry do. New
files are swapped in atomically and the mTLS client hot-reloads them on the next
handshake, so there is **no restart and no gap in data** as long as rotation
keeps succeeding.

Rotation is self-healing: a failed attempt retries every minute while the
current SVID is still valid, logging loudly. As an operator you mostly watch for
two things in the agent logs:

- `agent SVID rotated` — the healthy steady-state heartbeat of rotation working.
- `identity rotation FAILED (will retry; ingest stops if the SVID expires)` —
  the warning that matters. If you see this persisting, fix it (reachability to
  `identity.server`, a not-yet-revoked identity) **before** the 24-hour SVID
  expires, because once it does the agent's transport stops and its data dries
  up.

The full rotation protocol and security properties are in
[agent/enrollment.md](agent/enrollment.md).

### Staged fleet rollout

Upgrading the whole fleet at once is how one bad version takes everything down.
probectl instead moves a fleet to a new version in **waves** — a small canary
first, then early, then the rest — from **signed** artifacts, with the agent
registry **verifying** each wave and any failure **halting the train**.
Crucially, there is **no agent self-update**: agents never fetch or run new code
on their own (that would be a fleet-wide remote-code-execution primitive); the
control plane only *plans* and *verifies* waves while your orchestrator (Helm /
`install.sh` / config management) does the actual pushing. The full operator
runbook — plan, advance one wave, verify from the registry, halt-on-error, and
the explicit resume-with-a-note step — is in
[ops/fleet-rollout.md](ops/fleet-rollout.md).

## Transport posture

The shipped deployments are HTTPS-by-default (TLS + HSTS, no plaintext API). The
agent transport is mTLS with a SPIFFE-style, tenant-bound identity. Put the
control plane behind your TLS-terminating ingress (Helm) or use the bundled TLS
listener (compose); see [install.md](install.md).
