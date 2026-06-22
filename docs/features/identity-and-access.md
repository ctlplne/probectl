# Identity & access

## What it is

The way probectl decides *who you are* and *what you are allowed to do* — using
your own identity provider, never a password store of its own. Three pieces fit
together:

- **Single sign-on (SSO) over OpenID Connect (OIDC).** **SSO** lets people log in
  once with your corporate identity provider; **OIDC** is the standard web login
  protocol that makes it work. An **identity provider (IdP)** is the system that
  owns your user directory and runs the login page (Okta, Microsoft Entra ID,
  Keycloak, or one you self-host inside an air-gapped network). probectl trusts
  the IdP's word about who a user is and never sees or stores a password.
- **The access hierarchy.** A **tenant** (one isolated customer or organization)
  contains organizations, teams, and projects, and a user holds **roles** that
  grant permissions within that tenant.
- **Lifecycle and fine-grained control.** **System for Cross-domain Identity
  Management (SCIM)** lets your IdP *push* user create/update/delete into
  probectl. **Attribute-based access control (ABAC)** layers extra conditions on
  top of roles. **Delegated admin** lets a tenant administrator manage identity
  wiring without a platform operator.

The order of checks is the thing to remember, and it never changes: **tenant
boundary first, then role (role-based access control, RBAC), then attribute
(ABAC), and access fails closed** — anything not explicitly allowed is denied.
Terms of art (OIDC, SCIM, RBAC, ABAC, RLS) are in the [glossary](../glossary.md).

## Why it exists

A monitoring platform sees sensitive things — who your users are, where your
network breaks, which certificates are about to expire. Getting access control
wrong here is the highest-severity failure there is, because one tenant seeing
another tenant's telemetry is a breach. So probectl is built around two
principles.

First, **probectl should not be a second place your employee accounts live.** You
already run an IdP; it already knows who is hired and who left. Duplicating that
into probectl means two directories to keep in sync and two places to forget to
deprovision someone. Instead, the IdP stays the source of truth: it authenticates
logins (SSO) and it pushes the user roster (SCIM). When HR changes, access
changes — not the next time someone happens to log in.

Second, **a genuine identity is not the same as permission to act.** Think of the
IdP as a passport office and probectl as the border desk: the desk verifies the
passport is genuine, but a genuine passport is not a visa. Logging in proves who
you are; it does not decide what you may do. That is why a brand-new user arrives
with *no roles* and is denied every scoped resource until an administrator (or a
SCIM group sync) grants one. Deny-by-default is the secure starting point — you
add access deliberately, you never have to remember to take away an accidental
grant.

## How it works

**Login is the standard OIDC authorization-code flow.** You set the auth mode to
session and point probectl at your IdP's **issuer** (the HTTPS URL all its tokens
name as their origin). probectl sends the browser to the IdP; the IdP
authenticates the user and sends the browser back with a one-time code; probectl
exchanges that code for an **ID token** — a signed statement of facts about the
user. On the callback probectl validates the token's signature and a **nonce** (a
single-use random value minted at login that ties this token to this attempt, so
a captured token cannot be replayed — a mismatch fails the login closed), reads
the user's email, and just-in-time provisions a first-time user **with no roles**.

Crucially, **probectl does not read a `groups` claim off the login token and turn
it into roles.** A claim is a snapshot minted at sign-in: revoke a group in the
IdP and the stale claim keeps working until the next login. Permissions therefore
arrive one of two ways — a SCIM group sync (the directory speaking *now*), or an
administrator granting the role explicitly. The IdP's job is narrow and
well-defined: prove who the user is, and, for step-up policies, *how* they
authenticated (probectl derives a multi-factor-authentication flag from the
standard token fields naming the methods used).

**SCIM provisioning runs over a per-tenant bearer token.** A **bearer token** is
a secret string whose mere possession authenticates the request — whoever holds
it bears the access. Your IdP calls probectl's SCIM endpoints carrying that
token. The lookup is **pre-tenant**: the token *selects its own tenant*, and only
its hash is stored, so reading the database can never recover or mint a usable
token. Every provisioning action is then scoped by **row-level security (RLS)** —
the database itself refuses to return or write rows outside the current tenant,
regardless of what the query asks — so one tenant's IdP can never touch another
tenant's directory. A SCIM **Group maps to a probectl role**, and group
membership becomes a role binding; that mapping is what gives users their
permissions.

**Deprovisioning revokes access immediately.** When a user is deactivated or
deleted via SCIM, probectl deletes all of that user's sessions and revokes their
tool tokens *in the same request* — there is **no time-to-live window to wait
out**, and it does not depend on any cache. Think of a building badge confiscated
at the desk the moment HR terminates, rather than one that keeps opening doors
until its printed expiry. The next request on a deprovisioned session fails to
resolve.

**ABAC is a third check that can only narrow, never widen.** A single
authorization function evaluates the three layers strictly in order: the tenant
boundary fails closed on a cross-tenant resource *before* RBAC is even consulted,
so a stronger inner grant can never override the outer boundary; then RBAC
decides whether the role holds the permission; then ABAC policies can *deny*. The
model is deny-override: RBAC is the baseline grant, and ABAC can only take away
from it. RBAC says "this role may write tests"; ABAC adds "…but not if the subject
is a contractor." Building it one-way is deliberate — a policy language that can
*grant* is a second parallel permission system with two places to get wrong; one
that can only *subtract* keeps a single source of truth.

```text
request → resolve principal (tenant, permissions, attributes)
  └─ tenant boundary?    no → deny (fail closed, before RBAC)
       └─ RBAC permits?  no → 403
            └─ ABAC denies?  yes → 403 (denied by policy)
                 └─ otherwise → handler runs
```

The seeded system roles, one set per tenant: **admin** (full access within the
tenant, including reading and exporting the audit trail), **editor** (read
everything; manage tests, alerts, incidents), and **viewer** (read-only, no audit
access). Role bindings also carry an organization, team, or project scope, which
is how delegated admin works — a policy can confine an admin to a single
organization. The directory-admin permissions are seeded to the admin role, which
is what makes a *tenant* administrator able to manage SCIM tokens and ABAC
policies without involving a platform operator.

## Use it

**Point probectl at your IdP** (Helm values or environment). Any
standards-compliant OIDC provider works, including one inside an air-gapped
network:

```sh
PROBECTL_AUTH_MODE=session
PROBECTL_OIDC_ISSUER=https://keycloak.corp.example/realms/probectl
PROBECTL_OIDC_CLIENT_ID=probectl
PROBECTL_OIDC_CLIENT_SECRET=...        # inject from your secret manager, never commit
PROBECTL_OIDC_REDIRECT_URL=https://probectl.example/auth/callback
```

Register that redirect URL with your IdP. Login begins at `GET /auth/login`; the
session cookie is set Secure, HttpOnly, and SameSite=Lax — sent only over HTTPS,
unreadable to page scripts, and not attached to cross-site requests.

What you should observe on a first login: the user is created with **no roles**
and is denied scoped resources. Inspect your own effective access:

```sh
curl --cacert ca.crt "https://probectl.example/v1/me"
```

It returns the tenant you resolved to and the permission set you hold — empty for
a brand-new user until a role is granted.

**Mint a per-tenant SCIM token** (from Admin & Settings → Identity administration,
or the session-authenticated API), then paste it into your IdP's provisioning
config:

```sh
# Returns the plaintext bearer value ONCE — only its hash is stored, so copy it now.
curl --cacert ca.crt -X POST "https://probectl.example/v1/directory/scim-tokens" \
  -d '{"name":"okta"}'
```

The IdP then drives the roster: provisioning a user creates them, mapping a SCIM
group to a probectl role grants the permission, and deactivating a user revokes
access at once. What you should observe on deprovision: the user's next request
returns 401 immediately, with no waiting period.

**Add an ABAC policy** to narrow what a role grants — for example, block writes
for contractors:

```json
{
  "permission": "test.write",
  "effect": "deny",
  "subject": { "department": "contractor" },
  "priority": 100,
  "enabled": true
}
```

What you should observe: a user whose SCIM-provisioned `department` attribute is
`contractor` is denied `test.write` even though their role would otherwise allow
it — and no policy you can write will *grant* a permission RBAC did not already
give. Among matching policies the highest priority wins, and a deny wins ties.

## Pitfalls & limits

- **The order is fixed and fails closed.** Tenant first, then RBAC, then ABAC,
  deny by default. A cross-tenant request is rejected at the boundary before RBAC
  is consulted — no role or attribute can widen a request beyond its own tenant.
- **A new SSO user has no access on purpose.** Login does not grant roles. If a
  freshly logged-in user "can't see anything," that is the secure default — grant
  a role via SCIM group sync or explicitly as an admin.
- **Group claims on the login token are ignored — by design.** Permissions come
  from SCIM (the directory now) or an explicit grant, not from a `groups` claim
  (a stale snapshot). Wire roles through SCIM push, not OIDC claims.
- **ABAC can only subtract.** An ABAC `allow` is just a silent permit of
  something RBAC already allowed. There is no way to use ABAC to grant a
  permission a role lacks.
- **Outbound TLS to the IdP is always verified.** A self-signed IdP certificate
  from a private certificate authority is fine *only if that authority is in the
  trust store*. probectl never skips verification — "trust my private authority"
  extends who may vouch; "skip verification" would accept anyone, and login is
  the worst place to accept anyone.
- **One IdP per deployment, today.** A per-tenant-IdP factory exists, but
  database-backed per-tenant IdP configuration is still to come — until it lands,
  the single configured IdP is shared across tenants.
- **The unauthenticated dev mode is for local evaluation only.** It grants every
  request full access with no login; release binaries do not even contain it, and
  setting it makes the control plane refuse to start.
- **Not yet supported:** Security Assertion Markup Language (SAML) login, and
  pull-style directory connectors (Entra ID and Okta integrate via SCIM push plus
  OIDC SSO — no extra connector needed). Wiring per-handler resource attributes
  into ABAC is incremental.

## Reference

- **SSO config:** `PROBECTL_AUTH_MODE=session`, `PROBECTL_OIDC_ISSUER`,
  `PROBECTL_OIDC_CLIENT_ID`, `PROBECTL_OIDC_CLIENT_SECRET`,
  `PROBECTL_OIDC_REDIRECT_URL`, `PROBECTL_SESSION_TTL` (default 12h). Login at
  `GET /auth/login` → IdP → `GET /auth/callback`.
- **IdP contract:** expose the discovery document at
  `${issuer}/.well-known/openid-configuration`, issue ID tokens for the `openid`
  scope including an `email` claim, honor the nonce, and redirect back over HTTPS.
  Group and role plumbing is not part of this contract — it rides SCIM.
- **Seeded roles (per tenant):** `admin`, `editor`, `viewer`. Inspect your own
  access at `GET /v1/me`.
- **SCIM:** endpoints under `/scim/v2` (Users, Groups, and a discovery
  document), authenticated by a per-tenant bearer token. Manage tokens at `GET /
  POST / DELETE /v1/directory/scim-tokens`. A Group maps to a role; deactivation
  or deletion revokes sessions and tokens immediately.
- **ABAC:** policies managed at `/v1/abac/policies` (read gated by a
  directory-read permission, create and delete by directory-write). A policy
  matches when every listed subject and resource attribute equals the request's
  value; highest priority wins; deny wins ties. Subject attributes come from the
  SCIM-provisioned `attributes` plus a derived multi-factor flag.
- **Audited and tenant-scoped:** every provision, update, deprovision, policy
  change, and login writes to the tamper-evident audit trail, scoped to the
  tenant by RLS.
- **Related capabilities (separate pages):** the audit-log foundation (what every
  identity action is recorded into); SIEM export and on-call/ITSM routing (where
  audit and incident events flow); tenant isolation (the outermost boundary these
  checks sit inside).

**Covers:** F22, F24, F25
