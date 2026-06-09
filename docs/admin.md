# Administering probectl

Day-2 operation of an installed deployment: identity and roles, the audit trail,
and SSO. For installation see [install.md](install.md); for every config key see
[configuration.md](configuration.md).

## Identity, roles, and access (RBAC)

probectl enforces a **two-level boundary** on every API path: the request first
resolves to exactly one tenant, then RBAC decides whether the caller may perform
that route's action. Authentication is **OIDC SSO**
(`PROBECTL_AUTH_MODE=session`); the `dev` mode is for evaluation only and grants
all access — never run it in production.

Seeded system roles (one set per tenant):

| Role     | Capability |
| -------- | ---------- |
| `admin`  | Full access within the tenant, including reading/exporting the audit trail. |
| `editor` | Read everything; manage tests, alerts, and incidents. |
| `viewer` | Read-only across the planes (no audit access). |

A **new SSO user is created with no roles** (the secure default) and is denied
scoped resources until an admin grants one. Inspect your own effective access at
`GET /v1/me`. Role bindings live in the `role_bindings` table. Users and roles
within a tenant are provisioned by your IdP over **SCIM 2.0** (the `/scim/v2/...`
endpoints, authenticated by a per-tenant SCIM bearer token); deprovisioning a
user revokes their access.

## The audit trail

Every configuration change (creating, updating, or deleting a test, agent,
alert, or incident) and every authentication (the `auth.login` action) is
written to an **immutable, hash-chained, tamper-evident** audit log — in the
*same database transaction* as the action it records, and scoped to the tenant by
RLS. Provider-plane and break-glass actions go to a **separate** provider audit
stream.

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
connectors build on. probectl ships connectors for **syslog, CEF, ECS, and OTLP**
(select the wire format with `PROBECTL_SIEM_FORMAT`). The `audit.export`
permission gates streaming export.

## SSO (OIDC)

Configure a single IdP per deployment with `PROBECTL_OIDC_ISSUER`,
`PROBECTL_OIDC_CLIENT_ID`, `PROBECTL_OIDC_CLIENT_SECRET`, and
`PROBECTL_OIDC_REDIRECT_URL` (`https://HOST/auth/callback`). Register that
callback with your IdP. Login begins at `GET /auth/login`; the session cookie is
`Secure + HttpOnly + SameSite=Lax`, with lifetime `PROBECTL_SESSION_TTL`
(default 12 h). Per-tenant IdPs (a tenant bringing its own SSO) resolve through a
provider factory; the factory exists today, but DB-backed per-tenant IdP
configuration is still to come — until it lands, the single env-configured IdP is
shared across tenants.

## Transport posture

The shipped deployments are HTTPS-by-default (TLS + HSTS, no plaintext API). The
agent transport is mTLS with a SPIFFE-style, tenant-bound identity. Put the
control plane behind your TLS-terminating ingress (Helm) or use the bundled TLS
listener (compose); see [install.md](install.md).
