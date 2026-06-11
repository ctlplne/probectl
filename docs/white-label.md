# White-label / per-tenant branding

## What this is

**White-labeling** is shipping a product under the buyer's brand, with the
maker's name nowhere in sight. An MSP reselling probectl wants its customers to
see *its* brand, not probectl's
— and if it serves many customers, each of those may want *their own* brand
too. White-labeling makes that possible: per-tenant (and provider-master)
overrides of the design tokens, logo, product name, branded login page,
custom-domain mapping, and branded email templates.

The commercial machinery lives in **`ee/whitelabel`**, unlocked by the
`white_label` license feature (part of the Provider tier). The core seam — the
part that always answers "what brand am I?" — lives in **`internal/branding`**.
Community and unlicensed deployments simply serve the **default probectl
brand**: branding is **not lockware**, and the public brand endpoint never
404s, because a login page must always render.

### The mechanism in one sentence: it is a runtime token override

Every screen in the UI styles itself from **design tokens** — named design
values delivered as CSS custom
properties like `--color-primary`, never hardcoded colors (a CI gate enforces
"no hardcoded colors," including the commercial `ee/web` screens). Because
*everything* reads from tokens, branding is just a matter of **overriding those
token values at runtime** — zero per-screen work. The tokens are a theater's
lighting board: every scene is lit from the same named channels, so re-lighting
the whole show is sliding a few faders once — nobody repaints the sets. If some
screen can't be themed
by tokens alone, that is a token-coverage bug to fix in the design system
upstream, never a per-screen override bolted on here.

## The TenantBranding contract

A brand is stored per tenant (`tenant_branding`) or as the provider master
(`provider_branding`, the default for any tenant without its own row). Both
tables ship in migration `0027_branding.sql`. Two terms the field table leans
on: a **data URI** is an image embedded directly in the page as text
(`data:image/…;base64,…`), so displaying it requires no network fetch at all;
an **allowlist** names the only things permitted and refuses everything else by
default. The fields:

| Field | Notes |
|---|---|
| `product_name` | replaces the probectl wordmark + document title + email header |
| `logo_data_uri` | inline `data:image/(png\|jpeg\|svg+xml);base64`, ≤128KB — **no external fetches** (sovereignty; also keeps mail clients from phoning home) |
| `login_message` | copy shown on the branded login surface |
| `token_overrides` | design-token → value. **Allowlist**: `--color-*`, `--radius-sm/md/lg`, `--font-sans`, `--font-mono`. **Values are injection-safe by construction**: hex / `rgb()` / `hsl()` colors, simple lengths, font lists — no `url()`, no `var()`, no expressions. Validated in core (`internal/branding`, `ValidateOverrides`) **and** re-checked client-side |
| `email_from_name`, `email_footer` | email branding |
| `custom_domain` | one tenant per hostname (unique index), lowercase, no scheme/port |

**Resolution precedence: tenant row → provider master → probectl default**,
applied field by field (`merge` in `ee/whitelabel/whitelabel.go` folds master in
first, then the tenant on top). The key safety property: a resolution **failure
degrades to the default brand** — never an error page, and never another
tenant's brand.

### Why the value allowlist is so strict

Token overrides become CSS that probectl injects into the page. If an attacker
could smuggle `url(...)` or arbitrary expressions into a token value, that would
be a CSS-injection foothold — a `url()` value, for instance, makes every
visitor's browser silently call a server of the attacker's choosing. So the
validator accepts only a narrow set of
shapes — a hex/`rgb()`/`hsl()` color for `--color-*`, a simple length for
`--radius-*`, a plain font list for fonts — and rejects everything else. The
logo is constrained the same way: only a small inline `data:` image URI of a
safe type, never a fetchable URL.

## The no-bleed rule

The cardinal regression to prevent: **one tenant's brand must never bleed into
another's resolution.** The model is a coat check: every ticket names exactly
one coat — there is no "hand me whatever came in last." Three mechanisms
guarantee it:

- **Cache keys are strictly scoped.** The resolver caches under `t:<tenant-id>`,
  `h:<exact-host>`, or `master` — nothing broader (`Resolver` in
  `whitelabel.go`). A hot-cache A/B/A test proves switching tenants leaves no
  residue from the previous brand.
- **An authenticated tenant resolves by TENANT only.** A signed-in tenant-B
  user who happens to load tenant A's domain gets **B's** resolution, not A's
  brand. Host-to-tenant mapping is strictly the *pre-auth* path (`For` checks
  `tenantID` before it ever looks at `host`).
- **HTTP caching can't leak it either.** `/branding` responses set `Vary: Host`
  and `Cache-Control: private, max-age=60`, so a shared cache can never serve
  tenant A's brand on tenant B's domain (`handleBranding` in
  `internal/control/brandingapi.go`).

## Custom domains and login

`GET /branding` is **public and pre-auth** (mounted off `/v1`, like the
`/auth/*` routes, so it bypasses the session-RBAC chain). The single-page app
fetches it at boot, applies the token overrides to the `<html>` element, and
swaps the wordmark / logo / title.

When a request arrives on a mapped custom domain, that domain resolves to its
tenant's brand, and `GET /auth/login` logs into **that tenant** automatically —
no `?tenant=` needed (`handleLogin` calls `branding.TenantForHost`). An explicit
`?tenant=<UUID>` parameter still wins, for operator tooling.

**TLS for custom domains — the honest caveat:** probectl does **not** auto-issue
certificates in this release. Each custom domain needs a certificate at the
TLS-terminating ingress — issue and manage it there (cert-manager / ACME) or via
**trustctl**, the sibling certificate-lifecycle product (probectl's own TLS
posture view will then flag that domain's cert like any other). The onboarding
steps per domain are therefore: a DNS `CNAME` (an alias record pointing the
customer's hostname at the deployment), plus
an ingress certificate (the **ingress** being the TLS-terminating front door in
front of the control plane).

## Branded email templates

probectl's live email today is the alert engine's **plaintext SMTP channel**
(`internal/alert`); richer notifications ride the chat/on-call/ticket
integrations (Slack, Teams, PagerDuty, Opsgenie, ServiceNow, Jira —
`internal/notify`). None of those render a brand. So white-labeling ships the
**branded-HTML template contract** rather than wiring a mailer of its own:
`whitelabel.RenderEmail(brand, email)` wraps any notification body in the
tenant's brand (logo, product name, footer). It uses Go's `html/template`, so
every brand field is **escaped** — characters that could be read as HTML are
neutralized, so a brand string can never smuggle markup into the message — and
the logo is restricted to the
already-validated inline data URI (no external fetches in mail clients). When a
branded (HTML) email path lands, it renders through this and is branded for
free.

## Configuration surface

There are **no configuration keys** for white-labeling — activation is the
license feature, and brands are data, not config. Brands are managed from the
**provider console** (admin-only; brand changes are commercial decisions, so
they sit behind the provider role's separation of duties). The
**White-label branding** card writes:

- `PUT /provider/v1/tenants/{id}/branding` — a specific tenant's brand.
- `PUT /provider/v1/branding` — the provider master brand.

Those writes are audited as `provider.branding_set`. They are blocked
**read-only** by the license ladder when a license has expired past grace
(existing branding **persists** read-only — the "branding persists" promise
holds precisely because resolution is a read path, so it keeps working even when
writes are frozen). The whole card is **hidden** (returns not-found) when
`white_label` is not licensed.

Brands live in Postgres alongside the tenant registry and are never copied into
per-tenant silo schemas — the control plane serves branding. And the provider
console itself stays **probectl-branded**, deliberately visually distinct from
any tenant's brand, so an operator always knows they are in the management plane.
