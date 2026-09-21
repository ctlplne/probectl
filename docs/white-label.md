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
operator preference. **Light and dark** are the two shipped themes; light is the
default. An operator may additionally provide one token map for the entire
deployment:

```sh
PROBECTL_THEME_OVERRIDES='{"--primary":"28 85% 30%","--primary-foreground":"0 0% 100%"}'
```

A color value is the **bare HSL triplet** the stylesheet consumes — `28 85% 30%`,
or `28 85% 30% / 0.12` for a tint. The stylesheet reads each token as
`hsl(var(--token) / <alpha-value>)`, so a hex or `rgb()` value is refused with the
expected shape spelled out: accepting one would make every rule that uses the
token unparseable and paint the deployment wrong rather than differently.

Overridable names are the color tokens the stylesheet actually ships, plus
`--radius-control|panel|pill` and `--font-sans|mono|display`. The color allowlist
IS the shipped palette, so a token becomes overridable the moment it ships and a
name the palette does not define is refused instead of silently applied to
nothing. Spacing and type scale stay structural.

The control plane rejects browser-fetching/injection syntax, caps the map at 64
entries, and checks WCAG contrast against **both** shipped themes — so an override
that reads well in light but not dark fails startup rather than making one theme
unreadable. The browser repeats the grammar and contrast checks as defense in
depth.

Public `GET /branding` exposes only this deployment contract:

```json
{
  "product_name": "probectl",
  "token_overrides": {
    "--radius-panel": "10px"
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
