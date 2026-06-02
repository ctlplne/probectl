# Unified semantic query layer (S23)

`internal/ai` is netctl's unified, RBAC-aware query layer — one abstraction over
the stores (metrics, events/flows, entities, and the S30 topology graph) that the
API, the AI/RCA layer (S24), and the MCP server (S25) all use. It is **the
security boundary for AI and MCP**.

## Two-level scoping — tenant first, then RBAC

Every query enforces the tenant boundary **first**, then the caller's RBAC, at
this layer — never relying on a model to self-censor (CLAUDE.md §7 guardrails 1 & 5):

1. **Tenant (by construction).** A `Query` has **no tenant field**. The engine
   takes the tenant from the authenticated `auth.Principal`, so a caller cannot
   request another tenant's data; the tenant-keyed stores (e.g. the S30 topology
   store) inherit the S2 store-level scoping. A nil / empty-tenant principal fails
   closed (`ErrNoTenant`).
2. **RBAC.** Each domain requires a permission (`metrics.read`, `events.read`,
   `entities.read`, `topology.read`). A caller without it gets `ErrForbidden` (for
   a single query) or has that domain **silently skipped** (in a correlation) —
   never a partial leak.

`TestQueryLayerCrossTenantIsolation` proves a query cannot cross tenants.

## API

- `Engine.Query(ctx, principal, Query)` — a single-domain query.
- `Engine.Correlate(ctx, principal, subject, TimeRange)` — the cross-store join:
  it fans the subject across every domain the caller may read and returns one
  envelope with per-domain provenance.

## Result envelope

`Result{Tenant, Domains (provenance), Rows, Truncated, Elapsed}`. `Rows` are
normalized `map[string]any`; in a correlation each row carries `_domain`.

## Cost guards

`WithMaxRows` (default 1000) caps the rows and flags truncation; `WithTimeout`
(default 30s) bounds every query — LLM-generated queries can be expensive.

## Sources

The `MetricsSource` / `EventsSource` / `EntitiesSource` / `TopologySource`
interfaces are the seams to the durable stores (Prometheus/VictoriaMetrics,
ClickHouse, Postgres) and the topology graph. Each is tenant-scoped — the engine
passes the principal's tenant, never a tenant from the query. `NewTopologySource`
adapts the S30 store.

## Out of scope (later)

The LLM / RCA (S24); the MCP server (S25); NL parsing (S24/S26). This sprint is
the typed query API + planner + the two-level scoping boundary + the envelope +
cost guards those build on.
