# Frontend-coverage gate

## What it is

Every backend capability probectl ships needs _somewhere_ a user can actually
use it — a screen, a Grafana dashboard, an API. The frontend-coverage gate is a
test that fails the build if any declared capability has lost its user-facing
surface. It exists so backend and frontend can't silently drift apart: you add a
feature to the API, forget to wire up the screen, and nothing notices. This gate
notices.

Two pieces make it work:

- **The contract** — a registry, `web/src/surfaces.ts`. Every capability is one
  entry that declares _where_ it surfaces.
- **The enforcement** — a test, `web/src/test/surface-coverage.test.tsx`, run as
  the **Frontend-coverage gate** step of CI's `web` job (it runs
  `npm run coverage-gate`, which is `vitest run src/test/surface-coverage.test.tsx`).
- **The rendered a11y proof** — a Chromium gate, `npm run a11y:browser`, run by
  CI's `web-rendered-a11y` job in the digest-pinned Playwright container. It
  starts the real Vite app, renders every native route under the dark and aurora
  themes, runs axe with browser-computed WCAG tags, and checks keyboard focus,
  focus-obscured, positive `tabindex`, and 24px minimum interactive targets.
  The `/dashboards` route has an extra data-depth assertion in that same browser
  pass: active tests, BGP, flow, device, eBPF, cost, threat, and tenant-health
  dashboard tables must all render tenant-scoped fixture rows, and browser
  requests must not carry a `tenant_id` query parameter.

Think of the registry as a passenger manifest and the gate as the headcount:
drift in _either_ direction — someone aboard who isn't on the list, or someone
on the list who isn't aboard — fails the count. That bidirectionality is the
point; a one-way check would let the registry rot into fiction.

## The registry

Every entry declares one of three **Surface** kinds, and the gate checks a
different thing for each:

| Kind          | Meaning                                                                                  | What the gate verifies                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `native`      | A first-class screen in the app.                                                         | The route renders a _real_ screen (not the "coming soon" placeholder), has a `<main>` landmark (the HTML element assistive technology uses to jump straight to the page's content) and an `<h1>`, passes the jsdom `axe` screen test, and passes the rendered Chromium gate for browser-computed contrast, keyboard focus visibility/order safety, focus-obscured, and minimum interactive target size. |
| `federated`   | Surfaced through an external tool by design — Grafana, Prometheus, OTLP, or the raw API. | The declared evidence actually exists: a `file:<repo path>` is present on disk, and/or an `openapi:<path>` is a real route in the control plane's OpenAPI spec (`internal/control/openapi.json`). Federated surfaces **count** — the gate cares that a capability is reachable, not that it lives inside the app.                                                                                       |
| `none-by-design` | Deliberately no current surface.                                                     | The entry must carry a rationale and must not declare a route or federated evidence. Future or out-of-GA capabilities stay visible in the denominator without pretending a user-facing screen exists.                                                                                                                                                                                                     |

The gate fails on drift either way:

- a nav destination that nobody registered;
- a routed entry that isn't reachable from the nav (unless it is explicitly
  marked `offNav` — the provider/operator console is deliberately hidden from
  the tenant app);
- a `native` claim whose route renders the placeholder;
- a `none-by-design` claim with no rationale, or one that incorrectly declares
  a route or federated evidence;
- `federated` evidence that has disappeared;
- and, as a consistency check, any orphaned `routes/*.module.css` stylesheet
  that no route file imports.

## Working with it

Shipping a new surface means: add the screen **and** its registry entry in the
**same** pull request. Moving a capability from `none-by-design` to a real
surface means replacing the rationale with a `native` route or `federated`
evidence in that same change.
That's the whole discipline — the registry is the one place a declaration
becomes executable, so a forgotten screen turns into a red build instead of a
silent gap.

What the gate deliberately does **not** judge is design polish — it checks that
a capability is present, reachable, and accessible, not that it looks good. The
deeper per-page accessibility checks (empty states, loading states, data states)
live in `web/src/test/a11y.test.tsx`, while browser-only accessibility checks
live in `scripts/web_rendered_a11y.mjs`; visual quality stays a design-led,
human-reviewed concern.
