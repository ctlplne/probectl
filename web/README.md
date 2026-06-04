# web/ — probectl frontend foundation & design system (S8a)

The single frontend for probectl. This sprint establishes the **system** every
later UI surface builds on: design tokens, a component library, the app shell +
command palette, auth-aware routing, and a WCAG 2.2 AA baseline.

## Stack decision (the product-wide choice)

| Concern         | Choice                                  | Why |
| --------------- | --------------------------------------- | --- |
| Framework       | **React 18 + TypeScript + Vite**        | Richest ecosystem for data-dense observability UIs (tables, charts, the path/topology hero visuals); strong typing and tooling. |
| Styling/theming | **CSS custom properties + CSS Modules** | Tokens are read live, so per-tenant **white-label (F54)** is a *runtime token override*, not a per-screen rewrite. No utility-class lock-in; no external/"phone-home" fonts (sovereignty — CLAUDE.md §7 #11). |
| Server state    | **TanStack Query**                      | Caching/retries/loading-error states for the `/v1` API; UI state stays in React. |
| Routing         | **React Router**                        | Mature nested routing for the app-shell + outlet model. |
| Tests           | **Vitest + Testing Library + jest-axe** | Component, keyboard/focus, theme-swap, and an automated a11y gate — all runnable in CI without a browser. |

## Contracts established here

- **Design tokens** (`src/styles/tokens.css`) — the single source of design
  values. **No component hardcodes a color/space/type/radius/motion value.** A
  second theme (`[data-theme="aurora"]`) proves a full re-skin via token swap;
  per-tenant branding overrides the same set.
- **Component library** (`src/components/`) — Button, Card, Badge, Field, Table,
  Modal, Toast, ChartShell + Sparkline, and Empty/Error/Loading states. Browse
  them live at `/gallery`.
- **App shell + routes** (`src/shell/`, `src/routes/`) — sidebar IA (PRD §6.2),
  ⌘K command palette, always-visible tenant indicator, auth-aware routing.
- **Web API client + data pattern** (`src/api/`) — typed `apiFetch` against the
  versioned `/v1` API (tenant resolved server-side) wrapped in TanStack Query.

## Guardrails upheld

- **No hardcoded design values** — enforced by a test (`no-hardcoded-colors`).
- **White-label ready** — a token swap re-themes the whole UI (`theme` test).
- **WCAG 2.2 AA baseline** — semantic landmarks, skip link, focus management,
  reduced-motion, keyboard-first; an **axe gate** runs in CI. (Color contrast is
  fixed at the token layer; browser-based contrast checks come in PR2.)
- **Sovereignty** — no third-party network calls or external fonts.
- **Always-visible tenant indicator**; the shell resolves exactly one tenant.

## Develop

```bash
npm install
npm run dev        # Vite dev server (http://localhost:5173)
npm run build      # typecheck + production build
npm run test       # Vitest (a11y, theme-swap, command palette, token guard)
npm run lint       # ESLint
```

Stub auth (`src/auth/`) resolves a default tenant; it is replaced wholesale by
SSO/SCIM + the per-tenant IdP in **S18** behind the same `useAuth` contract.

## Deferred to PR2 (this is the spike-first foundation)

Storybook + the full component catalog with per-component stories and
browser-based visual/contrast tests. The token system, shell, and a11y gate they
build on are in place.
