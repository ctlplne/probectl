# Self-hosted / air-gapped OIDC IdP

**OIDC** (OpenID Connect) is the standard web login protocol: an **IdP**
(identity provider — the system that owns the user directory and the login
page) vouches for who a user is, and an application trusts that voucher
instead of keeping its own passwords. The IdP's identity on the network is its
**issuer** — the HTTPS URL all its tokens name as their origin.

probectl authenticates operators via **OIDC**: set `PROBECTL_AUTH_MODE=session`
and point it at an issuer with `PROBECTL_OIDC_ISSUER` plus a client id/secret
and redirect URL. Those values are the deployment fallback. A tenant admin may
configure a tenant-specific IdP in **Admin & Settings → Identity
administration** or through `PUT /v1/identity/settings`; an enabled tenant
configuration wins for that tenant. The secret is write-only at the API and
envelope-encrypted at rest with tenant-bound authenticated data. An absent or
disabled row uses the fallback, while a malformed or undecryptable enabled row
fails login closed. Nothing in probectl requires a *cloud* IdP — any
standards-compliant OIDC provider works, including one you run **inside the
air-gap.** That removes the last external dependency from a sovereign
deployment: telemetry never leaves the network — probectl's no-phone-home rule
(see the [non-negotiables](../../CONTRIBUTING.md#non-negotiables)) — and now
neither does the login flow.

## How probectl uses OIDC (and where roles come from)

probectl is a plain OIDC **relying party** (`internal/auth/oidc.go`, using
`go-oidc`) — the party that *relies on* the IdP's word rather than verifying
passwords itself. Login is the standard authorization-code flow handled at
`GET /auth/login` → IdP → `GET /auth/callback`: probectl sends the browser to
the IdP, the IdP authenticates the user and sends the browser back with a
one-time code, and probectl exchanges that code for an **ID token** — a signed
statement of **claims** (named facts about the user: email, name, how they
authenticated). The code exchange is bound to that exact browser login with
**PKCE S256**: probectl puts only a SHA-256-derived `code_challenge` in the
authorization request, keeps the random `code_verifier` in a short-lived
HttpOnly cookie, then sends the verifier directly to the IdP's token endpoint.
Someone who steals only the one-time code therefore cannot redeem it. A missing
verifier fails the callback closed. On a successful callback
(`internal/control/auth.go`) probectl:

1. validates the one-time authorization code with PKCE S256, then validates the
   ID token (signature, and the `nonce` it minted at login — a
   **nonce** is a single-use random value that ties this token to this login
   attempt, so a captured token cannot be replayed; a mismatch fails the login
   closed);
2. reads the user's **email** from the token;
3. **just-in-time provisions** a first-time user — created with **no roles**, a
   deliberately secure default.

That third point is the one thing to internalize: **OIDC gets a user *in the
door*; it does not decide what they can *do*.** Think of the IdP as a passport
office and probectl as the border desk: the desk verifies the passport is
genuine, but a genuine passport is not a visa — what you may do inside is
granted separately. probectl does **not** read a `groups` claim and turn it
into roles at login. Authorization (which RBAC roles a user holds) is assigned
one of two ways:

- **SCIM group sync** — the IdP pushes group membership to probectl, where a
  SCIM Group maps to a probectl role (see [SCIM + ABAC](../scim-abac.md)); or
- **an admin grants the role explicitly** in probectl.

Why not map `groups` claims to roles? A claim is a snapshot minted at sign-in
— revoke a group in the IdP and the stale claim keeps working until the next
login. SCIM is the directory speaking *now*, and its deprovision revokes
access immediately. So the IdP's job here is narrow and well-defined: prove
who the user is (and, for step-up policies, *how* they authenticated —
probectl derives an `mfa` flag from the ID token's `amr`/`acr` claims, the
standard fields naming the authentication methods used). Everything about
*permissions* is the SCIM/RBAC/ABAC path in [`scim-abac.md`](../scim-abac.md),
which is identical no matter which IdP you run — the self-hosted IdP is not a
special case.

## The contract

To be a valid IdP for probectl, the provider must:

- expose a discovery document at `${issuer}/.well-known/openid-configuration`
  reachable from the control plane (the discovery document is the IdP's
  self-description — endpoints, keys, capabilities — so nothing else needs
  hand-configuring; in-cluster DNS is fine);
- issue ID tokens for the `openid` scope, including an `email` claim (probectl
  requests `openid`, `email`, `profile` by default and refuses a login with no
  email);
- support OAuth 2.0 PKCE using the `S256` challenge method for the authorization
  code flow;
- honor the `nonce` (probectl validates it on the callback);
- redirect back to `${PROBECTL_OIDC_REDIRECT_URL}` over HTTPS.

That's the whole requirement. Group/role plumbing is *not* part of this
contract — it rides SCIM ([`scim-abac.md`](../scim-abac.md)).

## Reference: Dex (smallest air-gap footprint)

[Dex](https://dexidp.io) is a tiny OIDC provider with a static-password
connector — no external directory needed, which makes it ideal for an
air-gapped install. Run it in-cluster and point probectl at it:

```yaml
# dex-config.yaml (ConfigMap) — issuer is the in-cluster service URL
issuer: https://dex.probectl.svc.cluster.local:5556/dex
storage:
  type: kubernetes        # or sqlite3 on a PVC for a single replica
  config: { inCluster: true }
web:
  https: 0.0.0.0:5556
  tlsCert: /etc/dex/tls/tls.crt
  tlsKey: /etc/dex/tls/tls.key
staticClients:
  - id: probectl
    name: probectl
    secret: "${DEX_PROBECTL_CLIENT_SECRET}"   # = PROBECTL_OIDC_CLIENT_SECRET
    redirectURIs:
      - https://probectl.example/auth/callback # = PROBECTL_OIDC_REDIRECT_URL
enablePasswordDB: true
# staticPasswords: bootstrap an admin; thereafter wire an in-network LDAP if you have one
```

probectl side (Helm values or env):

```sh
PROBECTL_AUTH_MODE=session
PROBECTL_OIDC_ISSUER=https://dex.probectl.svc.cluster.local:5556/dex
PROBECTL_OIDC_CLIENT_ID=probectl
PROBECTL_OIDC_CLIENT_SECRET=...        # the Dex staticClient secret (pass by secret ref)
PROBECTL_OIDC_REDIRECT_URL=https://probectl.example/auth/callback
```

The Dex image is digest-pinned in your registry mirror like every other
air-gapped image (see the air-gapped bundle section of
[`hardening.md`](../hardening.md)).

## Reference: Keycloak (full-feature)

For larger orgs already running **Keycloak**, create a realm and a confidential
`probectl` client (standard flow, the redirect URI above) and point
`PROBECTL_OIDC_ISSUER` at `https://keycloak.internal/realms/<realm>`.
Keycloak's discovery and nonce handling satisfy the contract above unchanged.
Run it on an in-network host with its own datastore; nothing crosses the
air-gap. (If you want Keycloak to drive *roles*, do it via SCIM push, not OIDC
claims — see [`scim-abac.md`](../scim-abac.md).)

## Trust & TLS

The control plane validates the IdP's TLS certificate — outbound certificate
validation is never disabled anywhere in probectl (a
[non-negotiable](../../CONTRIBUTING.md#non-negotiables)). For an internal CA,
mount your CA bundle so the control plane trusts
the IdP's cert — the same trust store the rest of probectl uses for outbound
TLS. A self-signed IdP cert from a private CA is fine **as long as that CA is in
the trust store** — probectl never skips verification. The distinction matters:
"trust my private CA" extends the list of who may vouch; "skip verification"
would accept *anyone*, and login is the worst possible place to accept anyone.

## What's covered by tests vs. what you wire up

The OIDC relying-party path — discovery, PKCE S256 challenge/verifier binding,
nonce validation, the callback, and the `mfa`-from-`amr`/`acr` derivation — is
covered by the auth suite
(`internal/auth/oidc_test.go`, `oidc_mfa_test.go`). The IdP itself is
operator-run; standing up Dex in a disconnected cluster and completing a login
end-to-end is the deployment-time exercise, scripted by the values above.
