# Frontend-coverage gate (S-FE6)

Backend↔frontend coverage is a **verified, standing property** — not a thing
that silently drifts (the M-FE milestone existed because it did). The contract
is the capability→surface registry, `web/src/surfaces.ts`; the enforcement is
`web/src/test/surface-coverage.test.tsx`, run as the named
**Frontend-coverage gate** step in the CI `web` job (`npm run coverage-gate`).

## The registry

Every user-facing capability declares its **Surface**:

| Kind | Meaning | What the gate verifies |
| --- | --- | --- |
| `native` | A first-class screen on the S8a shell. | The route renders a real screen (never the placeholder), has a main landmark + h1, and passes the WCAG 2.2 AA axe bar. |
| `federated` | Served through an external surface by design (Grafana, Prometheus, OTLP, API). | The declared evidence exists: `file:<repo path>` and/or `openapi:<path>` in the control plane's spec. Federated surfaces COUNT — the gate checks coverage, not where it lives. |
| `placeholder` | The engine itself lands with the named sprint. | The route still renders the placeholder. When the screen ships, the entry must be re-declared `native` — the registry stays truthful both ways. |

Drift fails the build in both directions: a nav destination nobody registered,
a routed declaration outside the nav, a native claim that renders the
placeholder, a shipped screen still declared placeholder, federated evidence
that disappeared, and (consistency) any orphaned `routes/*.module.css`.

## Working with it

Shipping a new surface = add the screen **and** its registry entry (or flip
the placeholder entry to `native`) in the same PR. Forward sprints (S41+)
carry **Surface** declarations in the plan; the registry is where those
declarations become executable. The gate deliberately does **not** judge
design polish (the S-FE6 'watch out for') — the deeper per-page data-state
a11y checks live in `src/test/a11y.test.tsx`, and visual quality stays a
design-led concern (S11/S43/S24).
