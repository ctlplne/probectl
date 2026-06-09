# Self-hosted / air-gapped OIDC IdP

probectl authenticates operators via **OIDC**: set `PROBECTL_AUTH_MODE=session`
and point it at an issuer with `PROBECTL_OIDC_ISSUER` plus a client id/secret
and redirect URL. Nothing in probectl requires a *cloud* IdP — any
standards-compliant OIDC provider works, including one you run **inside the
air-gap.** That removes the last external dependency from a sovereign
deployment: telemetry never leaves the network (CLAUDE.md §7.2), and now
neither does the login flow.

## How probectl uses OIDC (and where roles come from)

probectl is a plain OIDC **relying party** (`internal/auth/oidc.go`, using
`go-oidc`). Login is the standard authorization-code flow handled at
`GET /auth/login` → IdP → `GET /auth/callback`. On a successful callback
(`internal/control/auth.go`) probectl:

1. validates the ID token (signature, and the `nonce` it minted at login — a
   mismatch fails the login closed);
2. reads the user's **email** from the token;
3. **just-in-time provisions** a first-time user — created with **no roles**, a
   deliberately secure default.

That third point is the one thing to internalize: **OIDC gets a user *in the
door*; it does not decide what they can *do*.** probectl does **not** read a
`groups` claim and turn it into roles at login. Authorization (which RBAC roles
a user holds) is assigned one of two ways:

- **SCIM group sync** — the IdP pushes group membership to probectl, where a
  SCIM Group maps to a probectl role (see `docs/scim-abac.md`); or
- **an admin grants the role explicitly** in probectl.

So the IdP's job here is narrow and well-defined: prove who the user is (and,
for step-up policies, *how* they authenticated — probectl derives an `mfa` flag
from the ID token's `amr`/`acr` claims). Everything about *permissions* is the
SCIM/RBAC/ABAC path in `docs/scim-abac.md`, which is identical no matter which
IdP you run — the self-hosted IdP is not a special case.

## The contract

To be a valid IdP for probectl, the provider must:

- expose a discovery document at `${issuer}/.well-known/openid-configuration`
  reachable from the control plane (in-cluster DNS is fine);
- issue ID tokens for the `openid` scope, including an `email` claim (probectl
  requests `openid`, `email`, `profile` by default and refuses a login with no
  email);
- honor the `nonce` (probectl validates it on the callback);
- redirect back to `${PROBECTL_OIDC_REDIRECT_URL}` over HTTPS.

That's the whole requirement. Group/role plumbing is *not* part of this
contract — it rides SCIM (`docs/scim-abac.md`).

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
air-gapped image (see the air-gapped bundle section of `docs/hardening.md`).

## Reference: Keycloak (full-feature)

For larger orgs already running **Keycloak**, create a realm and a confidential
`probectl` client (standard flow, the redirect URI above) and point
`PROBECTL_OIDC_ISSUER` at `https://keycloak.internal/realms/<realm>`.
Keycloak's discovery and nonce handling satisfy the contract above unchanged.
Run it on an in-network host with its own datastore; nothing crosses the
air-gap. (If you want Keycloak to drive *roles*, do it via SCIM push, not OIDC
claims — see `docs/scim-abac.md`.)

## Trust & TLS

The control plane validates the IdP's TLS certificate (guardrail 12, never
disabled). For an internal CA, mount your CA bundle so the control plane trusts
the IdP's cert — the same trust store the rest of probectl uses for outbound
TLS. A self-signed IdP cert from a private CA is fine **as long as that CA is in
the trust store** — probectl never skips verification.

## What's covered by tests vs. what you wire up

The OIDC relying-party path — discovery, nonce validation, the callback, and
the `mfa`-from-`amr`/`acr` derivation — is covered by the auth suite
(`internal/auth/oidc_test.go`, `oidc_mfa_test.go`). The IdP itself is
operator-run; standing up Dex in a disconnected cluster and completing a login
end-to-end is the deployment-time exercise, scripted by the values above.
