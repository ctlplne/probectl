# White-label / per-tenant branding — removed by design

Status: **not a product capability**. Owner decision recorded 2026-07-14.

MSPs self-host and resell probectl under the **probectl banner**. A tenant or
provider operator cannot replace the product name, mark/logo, login identity,
notification-email identity, or map a hostname to a tenant-specific brand.
PRD feature F54 remains in the traceability matrix as “removed by design” so
the capability is not silently forgotten or later mistaken for unfinished
work.

## What remains: deployment-level theming

The design-token system remains because it is useful for accessibility and
operator preference. Dark and aurora are the two shipped themes. An operator
may additionally provide one token map for the entire deployment:

```sh
PROBECTL_THEME_OVERRIDES='{"--color-accent":"#6a4cf0","--color-accent-hover":"#7054f6","--color-accent-strong":"#684af0","--color-accent-contrast":"#ffffff"}'
```

The control plane validates an allowlist of color, small radius, and font
tokens; rejects browser-fetching/injection syntax; caps the map at 64 entries;
and checks WCAG contrast against both shipped themes. An invalid set fails
startup rather than making the UI unreadable. The browser repeats the grammar
and contrast checks as defense in depth.

Public `GET /branding` exposes only this deployment contract:

```json
{
  "product_name": "probectl",
  "token_overrides": {
    "--radius-md": "10px"
  }
}
```

The response is pre-auth so the login shell can consume it, but it is not
tenant data: it is identical for every hostname, session, and tenant and is
cacheable for 60 seconds. `product_name` is fixed to `probectl`; the client also
rejects any response that attempts to replace it.

## API and storage removal

The provider-console branding card and the historical provider/tenant branding
routes were removed. `ee/whitelabel` was deleted, and no product-identity path
reads or writes `tenant_branding` or `provider_branding`. The generic,
count-verified tenant-offboarding path may still erase a tenant's deprecated row
during the compatibility window; it cannot use that row to influence the UI.

The two legacy tables are deliberately retained, inert, for one compatibility
release. Migration `0057_deprecate_branding_storage.sql` marks that contract
phase. Dropping them in the same rollout as the code removal would break an old
binary during a rolling deploy or rollback, violating the repository’s
expand/contract policy. A later release may add the destructive contract
migration only after its minimum-supported predecessor no longer accesses the
tables.
