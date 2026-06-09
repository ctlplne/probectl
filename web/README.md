# web/ — probectl frontend

The single frontend for probectl: a React + TypeScript app built on a design
system (tokens + component library) and an app shell. The design system is the
foundation every UI surface builds on — design tokens, a component library, the
app shell + command palette, auth-aware routing, and a WCAG 2.2 AA baseline —
and the product surfaces (results, topology, incidents, SLOs, cost, security,
the AI **Ask** panel, the provider console, and more) are routes on top of it.

## Stack

| Concern | Choice | Why |
| ------- | ------ | --- |
| Framework | **React 18 + TypeScript + Vite** | Richest ecosystem for data-dense observability UIs (tables, charts, the path/topology hero visuals); strong typing and tooling. |
| Styling/theming | **CSS custom properties + CSS Modules** | Tokens are read live, so per-tenant **white-label** is a *runtime token override*, not a per-screen rewrite. No utility-class lock-in; no external / "phone-home" fonts (sovereignty — CLAUDE.md §7 #11). |
| Server state | **TanStack Query** | Caching/retries/loading-error states for the `/v1` API; UI state stays in React. |
| Routing | **React Router** | Mature nested routing for the app-shell + outlet model. |
| Tests | **Vitest + Testing Library + jest-axe** | Component, keyboard/focus, theme-swap, and an automated a11y gate — all runnable in CI without a browser. |

## How it's organized (`src/`)

- **Design tokens** (`styles/tokens.css`) — the single source of design values.
  **No component hardcodes a color/space/type/radius/motion value.** A second
  theme (`[data-theme="aurora"]`) proves a full re-skin via token swap;
  per-tenant branding overrides the same set.
- **Component library** (`components/`) — Button, Card, Badge, Input, Select,
  Table, Modal, Toast, Icon, ChartShell + Sparkline, and Empty/Error/Loading
  states (`States`). Browse them live at `/gallery`.
- **App shell** (`shell/`, `nav/`) — sidebar IA, ⌘K command palette,
  always-visible tenant indicator, top bar.
- **Theming / branding** (`theme/`, `brand/`) — `ThemeProvider` (light/dark +
  the aurora demo theme) and `BrandProvider` (per-tenant white-label token
  overrides).
- **Auth** (`auth/`) — `AuthProvider` resolves the **real** signed-in identity
  from the session (`GET /v1/me`; the server resolves the tenant from the
  session cookie, never the browser) and exposes it through `useAuth`. There is
  no demo/stub identity: an unauthenticated caller is sent to SSO login.
- **API client** (`api/`) — a typed `apiFetch` (`client.ts`) against the
  versioned `/v1` API (tenant resolved server-side), wrapped in TanStack Query,
  with one module per surface (`results.ts`, `topology.ts`, `ai.ts`, …).
- **Surfaces** (`routes/`, `surfaces.ts`) — the product pages (results, path,
  topology, incidents, alerts, SLOs, cost, security/threat, endpoints,
  compliance, outages, the AI Ask panel, authoring) plus the provider/commercial
  surfaces. `surfaces.ts` is the registry the surface-coverage gate checks.

## Guardrails upheld

- **No hardcoded design values** — enforced by a test
  (`test/no-hardcoded-colors.test.ts`).
- **White-label ready** — a token swap re-themes the whole UI
  (`test/theme.test.tsx`).
- **WCAG 2.2 AA baseline** — semantic landmarks, skip link, focus management,
  reduced-motion, keyboard-first; an **axe gate** runs in CI
  (`test/a11y.test.tsx`).
- **Surface coverage** — every user-facing capability declares a surface;
  `test/surface-coverage.test.tsx` (`npm run coverage-gate`) fails the build on
  a capability with no surface (CLAUDE.md §8).
- **Sovereignty** — no third-party network calls or external fonts.
- **Always-visible tenant indicator**; the shell resolves exactly one tenant.

## Develop

```bash
npm install
npm run dev          # Vite dev server (http://localhost:5173)
npm run build        # typecheck (tsc --noEmit) + production build
npm run test         # Vitest (a11y, theme-swap, command palette, surface coverage, per-surface tests)
npm run coverage-gate # the surface-coverage gate on its own
npm run lint         # ESLint
```

The dev server proxies `/v1` and `/provider` to a locally-running control plane
(`http://localhost:8080` by default — see `vite.config.ts`); production serves
the bundle **same-origin behind the TLS ingress** (HTTPS/CSP/HSTS are enforced
by the ingress, not Vite). HTTPS-by-default and no external origins are the
sovereignty contract (CLAUDE.md §7 guardrails 11–12).

## Editions boundary in the UI

Commercial UI source lives in `ee/web` and is aliased as `@ee` (the editions
boundary applies to the frontend too). The bundle always includes it; visibility
is **runtime-gated** — unlicensed surfaces 404 at the API, so commercial features
are hidden rather than shipped as lockware (CLAUDE.md §2).
