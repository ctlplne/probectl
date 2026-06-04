# Administering probectl

Day-2 operation for an installed deployment: identity and roles, the audit trail,
and SSO. For installation see [`install.md`](install.md); for every config key see
[`configuration.md`](configuration.md).

## Identity, roles, and access (RBAC)

probectl enforces a **two-level boundary** on every API path: the request resolves
to exactly one tenant first, then RBAC decides whether the caller may perform the
route's action. Authentication is **OIDC SSO** (`PROBECTL_AUTH_MODE=session`); the
`dev` mode is for evaluation only and grants all access.

Seeded system roles (per tenant):

| Role     | Capability |
| -------- | ---------- |
| `admin`  | Everything within the tenant, including reading/exporting the audit trail. |
| `editor` | Read everything; manage tests, alerts, and incidents. |
| `viewer` | Read-only across the planes (no audit access). |

A **new SSO user is created with no roles** (secure default) and is denied scoped
resources until an admin grants one. Inspect your own effective access at
`GET /v1/me`. Role bindings live in the `role_bindings` table; a console for
managing users/roles within a tenant lands with SCIM (S31).

## The audit trail

Every configuration change (test/agent/alert/incident create, update, delete) and
authentication (`auth.login`) is written to an **immutable, hash-chained,
tamper-evident** audit log, in the same database transaction as the action it
records, scoped to the tenant by RLS. Provider-plane and break-glass actions go to
a separate provider audit stream.

Read and verify it (requires the `audit.read` permission — admin by default):

```sh
# A page of the tenant's audit trail, newest cursor returned as "next".
curl --cacert ca.crt "https://HOST/v1/audit?after=0&limit=100"

# Verify chain integrity (ok=false with a detail if any record was altered).
curl --cacert ca.crt "https://HOST/v1/audit/verify"
```

Each event carries `seq`, `actor`, `action`, `target`, optional `data`, and the
`prev_hash`/`hash` chain links. Re-computing the chain detects any insertion,
deletion, reordering, or tampering.

### Exporting to a SIEM

The audit log is built for export. `GET /v1/audit?after=<cursor>` is a pull cursor
(advance `after` to the last `seq` you've consumed). Programmatic export is the
`audit.Sink` hook plus `audit.Drain` (read a page → deliver → advance cursor) —
the stable contract the SIEM connectors (syslog/CEF/OTLP) build on in S32. The
`audit.export` permission gates streaming export.

## SSO (OIDC)

Configure a single IdP per deployment with `PROBECTL_OIDC_ISSUER`,
`PROBECTL_OIDC_CLIENT_ID`, `PROBECTL_OIDC_CLIENT_SECRET`, and
`PROBECTL_OIDC_REDIRECT_URL` (`https://HOST/auth/callback`). Register that callback
with your IdP. Login begins at `GET /auth/login`; the session cookie is
`Secure + HttpOnly + SameSite=Lax`, lifetime `PROBECTL_SESSION_TTL` (default 12h).
Per-tenant IdPs (a tenant bringing its own SSO) are resolved through a provider
factory; DB-backed per-tenant IdP config arrives in a later sprint.

## Transport posture

The shipped deploys are HTTPS-by-default (TLS + HSTS, no plaintext API). The agent
transport is mTLS with SPIFFE-style, tenant-bound identity. Put the control plane
behind your TLS-terminating ingress (Helm) or use the bundled TLS listener
(compose); see [`install.md`](install.md).
