# Frontend-coverage gate

## What it is

Every backend capability probectl ships needs *somewhere* a user can actually
use it — a screen, a Grafana dashboard, an API. The frontend-coverage gate is a
test that fails the build if any declared capability has lost its user-facing
surface. It exists so backend and frontend can't silently drift apart: you add a
feature to the API, forget to wire up the screen, and nothing notices. This gate
notices.

Two pieces make it work:

- **The contract** — a registry, `web/src/surfaces.ts`. Every capability is one
  entry that declares *where* it surfaces.
- **The enforcement** — a test, `web/src/test/surface-coverage.test.tsx`, run as
  the **Frontend-coverage gate** step of CI's `web` job (it runs
  `npm run coverage-gate`, which is `vitest run src/test/surface-coverage.test.tsx`).

## The registry

Every entry declares one of three **Surface** kinds, and the gate checks a
different thing for each:

| Kind | Meaning | What the gate verifies |
| --- | --- | --- |
| `native` | A first-class screen in the app. | The route renders a *real* screen (not the "lands in a later sprint" placeholder), has a `<main>` landmark and an `<h1>`, and passes the WCAG 2.2 AA accessibility bar (via `axe`). |
| `federated` | Surfaced through an external tool by design — Grafana, Prometheus, OTLP, or the raw API. | The declared evidence actually exists: a `file:<repo path>` is present on disk, and/or an `openapi:<path>` is a real route in the control plane's OpenAPI spec (`internal/control/openapi.json`). Federated surfaces **count** — the gate cares that a capability is reachable, not that it lives inside the app. |
| `placeholder` | The feature itself isn't built yet; the screen is a stub. | The route still renders the placeholder. When the real screen ships, the entry **must** be flipped to `native` — which keeps the registry honest in both directions. |

The gate fails on drift either way:

- a nav destination that nobody registered;
- a routed entry that isn't reachable from the nav (unless it is explicitly
  marked `offNav` — the provider/operator console is deliberately hidden from
  the tenant app);
- a `native` claim whose route renders the placeholder;
- a shipped screen still declared `placeholder`;
- `federated` evidence that has disappeared;
- and, as a consistency check, any orphaned `routes/*.module.css` stylesheet
  that no route file imports.

## Working with it

Shipping a new surface means: add the screen **and** its registry entry (or flip
the existing `placeholder` entry to `native`) in the **same** pull request.
That's the whole discipline — the registry is the one place a declaration
becomes executable, so a forgotten screen turns into a red build instead of a
silent gap.

What the gate deliberately does **not** judge is design polish — it checks that
a capability is present, reachable, and accessible, not that it looks good. The
deeper per-page accessibility checks (empty states, loading states, data states)
live in `web/src/test/a11y.test.tsx`; visual quality stays a design-led,
human-reviewed concern.
