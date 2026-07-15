# Truthful data states and isolated demo mode

X18 turns “empty” into an explicit data contract. A native tenant-data surface must classify
the server response as exactly one of:

| State             | Meaning                                                                                  | It must not render                                               |
| ----------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Ready, no data    | The producer answered successfully but has not produced a record yet.                    | A zero chart or inferred healthy table.                          |
| Blocked           | The server reports the producer/engine is not running or is not configured.              | A quiet/healthy state.                                           |
| Permission denied | The tenant-scoped API returned `403`.                                                    | A retry that widens authority or a generic empty table.          |
| Degraded          | The query failed, a store is unavailable, or the server reports partial coverage.        | Cached samples presented as current truth.                       |
| Quiet             | A ready producer authoritatively returned no events for the selected observation window. | “Not configured” copy or a fabricated zero series.               |
| Demo              | The product-wide isolated sample workspace is active.                                    | Any live tenant route, query, export, alert, or incident action. |

`HonestDataState` requires four facts on every state: producer readiness, the last successful
ingest when the server reports one, the exact coverage limitation, and one authorization-safe
next action. `classifySurfaceTruth` gives permission and failure states precedence over empty
results, so an unavailable store cannot become a healthy-looking zero.

The audited route inventory is `web/src/data/surfaceTruth.ts`. The surface-coverage test fails
when a new native data route does not declare its producer truth, ingest timestamp source,
coverage source, safe action, and all six states.

## Demo mode

Enter the operator demo by opening any tenant route with `?demo=1`, for example
`/targets?demo=1`. Entry is intentionally URL-explicit; it is not a remembered tenant
preference and uses no browser storage.

While active:

- a persistent warning banner says that all values are sample data;
- every illustrative panel also carries a **Demo data** badge;
- the tenant route outlet is not mounted, so route data hooks, exports, alerts, and incident
  actions do not exist in the rendered tree;
- the shared API client independently fails closed for every tenant endpoint except the
  authenticated identity bootstrap; and
- navigating elsewhere in the tenant shell keeps the isolated workspace active.

Press **Shift+D** to exit. This is the single direct keyboard command: it removes the URL
marker, drops the transport isolation, and only then mounts the live tenant route. “Exit demo
mode” is also discoverable in the command palette while the mode is active.

## Verification

```sh
cd web
npm test -- src/test/empty-states.test.tsx src/test/demo-mode.test.tsx src/test/surface-coverage.test.tsx
```

The fixtures cover all six classifications, `running:false`, failed and forbidden requests,
degraded feed health, a genuinely quiet observation window, persistent demo badges, transport
denial, and the Shift+D transition back to live data.
