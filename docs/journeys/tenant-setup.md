# Stand up and isolate a tenant (MSP / provider)

You run probectl for many customers as a managed service provider
([glossary](../glossary.md)) — an **MSP**. This journey walks you from an empty
provider plane to a single tenant that is isolated, branded, metered, and wired to
its own users. By the end the tenant's people can log in and see only their own
data — and you, the operator, still cannot read their telemetry.

That last point is the spine of this journey. A provider operator lives in a
*separate* privilege domain from a tenant's users. Provisioning a tenant gives you
zero implicit read access to its network telemetry. The only path into a tenant's
data is audited break-glass that the *tenant* itself approves — covered on the
provider plane page, deliberately not part of standing setup.

## Who this is for

- An MSP or internal platform-team operator who runs one deployment for many
  customers.
- An operator authenticated to the provider plane with multi-factor login (the
  plane requires it; there is no password-only sign-in).
- Anyone standing up a new customer tenant end to end: isolation, branding,
  identity, and billing.

## Before you start

- A provider plane that is licensed and running (it refuses to start without a
  deployment encryption key). The license's tenant band caps how many tenants you
  may provision.
- A provider operator account, enrolled with a time-based authenticator code.
- For the tenant's identity wiring: the customer's OpenID Connect
  ([glossary](../glossary.md)) — **OIDC** — issuer, client id, and client secret.
- The control plane's certificate authority file (`./ca.crt`) for the
  session-authenticated routes. Note that `/provider/v1/tenants` and
  `/provider/v1/usage/export` are provider-plane routes.

## The path

1. **Provision a tenant from the provider plane.** Create the customer's tenant;
   the license's tenant band is enforced here:

   ```sh
   curl --cacert ./ca.crt -X POST \
     -H "Authorization: Bearer $OPERATOR_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"slug":"acme","name":"Acme Corp","isolation_model":"pooled"}' \
     https://control.example/provider/v1/tenants
   ```

   You observe a created tenant. Provisioning past the licensed band fails loudly
   with `tenant_band_exhausted`, and existing tenants are never affected. Powered
   by [the provider / MSP plane](../features/commercial-plane.md).

2. **Choose the isolation model.** Decide how hard the wall is: `pooled` (shared
   stores, told apart by a tenant identifier — the default), `siloed` (its own
   schema, telemetry database, channels, and storage namespace), or `hybrid` (a
   pooled control plane with a per-tenant telemetry database). Set
   `isolation_model` in the body above; siloed and hybrid require the licensed
   tier.

   ```json
   { "slug": "acme", "name": "Acme Corp", "isolation_model": "siloed", "residency": "eu" }
   ```

   You observe the isolated stores created *before* the call returns — a siloed
   tenant never exists without its silo, and physical separation stacks on top of
   the storage-layer scoping, never instead of it. Powered by
   [tenancy and hard isolation](../features/tenancy.md).

3. **Set fairness quotas so no tenant starves others.** Read the tenant's effective
   fairness posture and live accounting, then tune the ingest and query bounds so
   one noisy tenant cannot slow the shared pipeline:

   ```sh
   # Operator view across tenants, then set one tenant's tune.
   curl --cacert ./ca.crt -H "Authorization: Bearer $OPERATOR_TOKEN" \
     https://control.example/provider/v1/fairness

   curl --cacert ./ca.crt -X PUT \
     -H "Authorization: Bearer $OPERATOR_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"ingest_rate_per_sec":5000,"query_budget":200}' \
     https://control.example/provider/v1/tenants/{id}/fairness
   ```

   You observe the effective limits and counters: `admitted_calls` and
   `admitted_units` climb with normal traffic, `shed_calls` and `shed_units` are
   non-zero only if ingest exceeded its rate. Fairness bounds *rates*, never
   lifetime totals, and never drops telemetry. Powered by
   [tenancy and hard isolation](../features/tenancy.md).

4. **Apply white-label branding.** Re-brand the tenant by overriding named design
   values at runtime — product name, inline logo, login message, a narrow
   injection-safe allowlist of colors and typography, and a custom-domain mapping.
   There is no per-screen work, and one tenant's brand never bleeds into another's.

   You observe the tenant's people seeing their own brand; a resolution failure
   degrades to the default brand, never another tenant's. Powered by
   [the provider / MSP plane](../features/commercial-plane.md).

5. **Connect single sign-on and SCIM provisioning.** Point the tenant at its own
   OIDC identity provider, then mint a per-tenant System for Cross-domain Identity
   Management ([glossary](../glossary.md)) — **SCIM** — token so the directory can
   push users:

   ```sh
   # Returns the plaintext bearer value ONCE — only its hash is stored, copy it now.
   curl --cacert ./ca.crt -X POST \
     -H "Authorization: Bearer $TENANT_ADMIN_TOKEN" \
     -d '{"name":"okta"}' \
     https://probectl.example/v1/directory/scim-tokens
   ```

   You observe a first-time user provisioned with **no roles** until a SCIM group
   maps to a role; deactivating a user revokes their sessions immediately, with no
   wait. Powered by [identity and access](../features/identity-and-access.md).

6. **Export usage for billing.** Pull the vendor-neutral metering feed for the
   current period — probectl exports counts; it is not an invoicing engine:

   ```sh
   curl --cacert ./ca.crt -H "Authorization: Bearer $OPERATOR_TOKEN" \
     'https://control.example/provider/v1/usage/export?format=csv'
   ```

   You observe one row per tenant per meter: counters (results ingested, ingest
   bytes, flow events, AI calls) summed over the period, gauges (agents, tests)
   reported at their peak. The columns are a stable, additive contract so your
   importer never breaks. Powered by
   [the provider / MSP plane](../features/commercial-plane.md).

## You're done when

- An isolated, branded, metered tenant exists with its own users provisioned by
  its own directory.
- The fairness posture is set so the tenant cannot starve neighbors, and its usage
  is exporting for billing.
- You, the operator, still have **no implicit read access** to the tenant's
  telemetry — the only way in is the tenant-approved, audited break-glass path.

## Next

Now tune that tenant's spend and service-level objectives in
[Govern cost and SLOs](./cost-and-slo-governance.md).

**Journey:** J4 · **Visits:** F50, F51, F52, F53, F54, F57, F22, F25
