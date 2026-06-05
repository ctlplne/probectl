# White-label / per-tenant branding (S-T4, F54-full)

An MSP resells under **its** brand: per-tenant (and provider-master)
overrides of the S8a design tokens, logo, product name, branded login,
custom-domain mapping, and branded email templates. Lives in
**`ee/whitelabel`**, unlocked by the `white_label` license feature.
Community/unlicensed deployments serve the **default probectl brand** —
branding is not lockware and the public brand endpoint never 404s (a login
page must always render).

**The mechanism is the S8a token contract, full stop.** Because every screen
styles itself from design tokens (the no-hardcoded-colors gate enforces it,
including `ee/web`), branding is a *runtime token override* — zero per-screen
work. If any screen can't be themed by tokens alone, that is an S8a
token-coverage bug to fix upstream, never a per-screen override here.

## The TenantBranding contract

Per tenant (migration 0027, `tenant_branding`) or provider-master
(`provider_branding`, the default for tenants without their own row):

| Field | Notes |
|---|---|
| `product_name` | replaces the probectl wordmark + document title + email header |
| `logo_data_uri` | inline `data:image/(png|jpeg|svg+xml);base64` ≤128KB — **no external fetches** (sovereignty; mail clients too) |
| `login_message` | branded login surface copy |
| `token_overrides` | S8a token → value. **Allowlist**: `--color-*`, `--radius-sm/md/lg`, `--font-sans`, `--font-mono`. **Values are injection-safe by construction**: hex/rgb()/hsl() colors, simple lengths, font lists — no `url()`, no `var()`, no expressions, validated in core (`internal/branding`) AND re-checked client-side |
| `email_from_name`, `email_footer` | email branding |
| `custom_domain` | one tenant per hostname (unique), lowercase, no scheme/port |

Resolution precedence: **tenant row → provider master → probectl default**,
field by field. A resolution failure degrades to the *default* brand — never
an error, never another tenant's brand.

## The no-bleed rule (the S-T4 regression)

One tenant's brand must never bleed into another's resolution:

- Resolver cache keys are **strictly** per tenant (`t:<id>`), per exact host
  (`h:<host>`), or the master — proven by `TestNoBleedRegression` (hot-cache
  A/B/A loops) and the client test (switching brands removes the previous
  brand's overrides with no residue).
- **An authenticated tenant resolves by TENANT only** — a signed-in tenant-B
  user on tenant A's domain gets B's resolution, not A's brand. Host mapping
  is the *pre-auth* path.
- `/branding` responses set `Vary: Host` + `Cache-Control: private` so a
  shared cache can never serve A's brand on B's domain.

## Custom domains + login

`GET /branding` is **public and pre-auth** (mounted off /v1 like /auth/*):
the SPA fetches it at boot, applies token overrides to `<html>`, and swaps
the wordmark/logo/title. A request arriving on a mapped custom domain
resolves that tenant's brand, and `GET /auth/login` logs into **that
tenant** automatically (an explicit `?tenant=` still wins).

**TLS for custom domains (the watch-out, honestly):** probectl does NOT
auto-issue certificates in this release. Each custom domain needs a cert at
the TLS-terminating ingress — issue/manage it there (cert-manager/ACME) or
via **trustctl** (the sibling lifecycle product; probectl's TLS posture view
will flag the domain's cert like any other). Document per-domain DNS
(CNAME → the deployment) + ingress cert as the onboarding steps.

## Branded email templates

probectl has no SMTP sender yet (S33 notifications ride Slack/Teams/
PagerDuty/ServiceNow/Jira), so S-T4 ships the **template contract**:
`whitelabel.RenderEmail(brand, email)` wraps any notification body in the
tenant's brand (logo/product name/footer, hostile fields escaped via
html/template, logo restricted to validated inline data URIs). When an email
channel lands it renders through here and is branded for free.

## Configuration surface

Provider console (admins; SoD — brand changes are commercial decisions):
the **White-label branding** card writes
`PUT /provider/v1/tenants/{id}/branding` and `PUT /provider/v1/branding`
(master). Audited (`provider.branding_set`); blocked read-only by the
license ladder (existing branding **persists** read-only — the S-T0 promise
"branding persists" holds because resolution is read-path only); hidden
(404) when `white_label` is not licensed. The provider console itself stays
probectl-branded — deliberately visually distinct from any tenant brand.

No configuration keys: activation is the license feature; brands live in
Postgres alongside the tenant registry (never copied into silo schemas —
the control plane serves branding).
