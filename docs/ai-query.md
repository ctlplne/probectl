# The unified semantic query layer

## What it is

`internal/ai` is probectl's **one way to read data across the platform**. probectl
stores different kinds of telemetry in different places — metrics in a time-series
DB (Prometheus/VictoriaMetrics), high-cardinality events and flows in ClickHouse,
durable entities like tests/agents/incidents in Postgres, and the live network map
in the topology graph. Instead of teaching every feature how to talk to four
different stores, everything reads through a single typed engine: `ai.Engine`.

The REST API, the AI root-cause assistant (`docs/ai-rca.md`), and the MCP server
(`docs/mcp.md`) all go through this same engine. That matters because the engine is
also **the security boundary for AI and MCP** — the one place where "which tenant
is asking, and what are they allowed to see?" is decided, *below* any model and
*below* handler code.

Think of it as a librarian who only ever hands you books from your own building,
and only the sections your badge opens. You never get to name the building.

## The core idea: the query has no tenant field

Here is the single most important design decision, and it's worth understanding
deeply because the whole isolation guarantee rests on it.

A query is this struct (`internal/ai/query.go`):

```go
type Query struct {
    Domain   Domain            // metrics | events | entities | topology
    Selector map[string]string // filters: metric name, prefix, node id, …
    Range    TimeRange
    Limit    int
    // topology traversal
    From, To, NodeID string
}
```

Notice what is **not** there: a tenant field. There is no way to write
`Query{Tenant: "acme"}`, because the type doesn't have that field. The engine
takes the tenant from the **authenticated caller** (`auth.Principal`), never from
the query. So a request — including one a language model helped build, or one
assembled from attacker-controlled text — *cannot even express* "give me another
tenant's data." It's not blocked at runtime; it's impossible to say.

This is the difference between "we check a tenant parameter" (which can be
forgotten, spoofed, or fuzzed) and "there is no tenant parameter to get wrong."

## Two-level scoping: tenant first, then RBAC

Every read enforces two gates, in this order, and both **fail closed** (when in
doubt, return nothing). This mirrors the platform-wide rule: tenant isolation is
the outermost boundary, RBAC sits inside it, and neither relies on a model
behaving itself.

**Gate 1 — Tenant (by construction).** `Engine.Query` starts with:

```go
if p == nil || p.TenantID == "" {
    return Result{}, ErrNoTenant
}
```

A caller with no tenant is rejected outright (`ErrNoTenant`). The tenant that
*does* get used is `p.TenantID` from the principal, which the engine passes down
to the store. The stores are themselves tenant-scoped (the topology store is keyed
by tenant; the Postgres-backed sources open a row-level-security transaction), so
even if the query layer had a bug, the storage layer is a second, independent
fence. Defense in depth.

**Gate 2 — RBAC (per domain).** Each domain needs a read permission, mapped one to
one in `internal/ai/permissions.go`:

| Domain     | Store                                      | Permission        |
| ---------- | ------------------------------------------ | ----------------- |
| `metrics`  | Prometheus / VictoriaMetrics               | `metrics.read`    |
| `events`   | ClickHouse (flows / threat / change / bgp) | `events.read`     |
| `entities` | Postgres (tests / agents / incidents)      | `entities.read`   |
| `topology` | the topology graph                         | `topology.read`   |

A caller missing the permission gets `ErrForbidden` for a single-domain query.
The crucial subtlety is what happens in a *correlation* (the cross-domain join):
domains the caller may not read are **silently skipped**, not error'd. That's
deliberate — a correlation should return everything you *can* see without leaking
the *existence* of what you can't, and without failing the whole answer because
one plane was off-limits. Never a partial leak; never a noisy "you can't see X."

`TestQueryLayerCrossTenantIsolation` (`internal/ai/isolation_test.go`) proves a
query issued as tenant A cannot return tenant B's rows.

## The two operations

The engine exposes exactly two methods (`internal/ai/engine.go`):

- `Engine.Query(ctx, principal, Query)` — a **single-domain** read. Runs the two
  gates, then dispatches to the one store the query names.
- `Engine.Correlate(ctx, principal, subject, TimeRange)` — the **cross-store
  join**. It fans one subject (e.g. a host, an IP, a prefix, a node) across *every*
  domain the caller may read, in a fixed order, and returns a single envelope.
  Each result row is tagged with `_domain` so you can tell which store it came
  from. This is how a question about one entity gathers evidence from metrics,
  events, entities, and topology in one shot.

## What comes back: the result envelope

Both methods return one normalized `Result` (`internal/ai/result.go`):

```go
type Result struct {
    Tenant    string   // the caller's tenant — the scope of this result
    Domains   []Domain // which domains actually contributed (provenance)
    Rows      []Row    // Row is map[string]any; in a correlation each carries _domain
    Truncated bool     // a cost guard capped the rows
    Elapsed   time.Duration
}
```

`Domains` is provenance: it tells you (and the UI, and the auditor) exactly which
planes the answer drew from — useful both for trust and for spotting "this plane
returned nothing." Rows are loosely typed (`map[string]any`) on purpose, because
four very different stores feed into one shape; the layers above (e.g. the RCA
evidence builder) pick out the well-known keys they care about.

## Cost guards: LLM-built queries can be expensive

A model — or a careless caller — can ask for a lot. Two guards bound every query,
set when the engine is constructed (`NewEngine`, defaults shown):

- **`WithMaxRows`** (default `1000`) caps the rows returned and sets
  `Truncated: true` when it bit, so the caller knows the answer was clipped rather
  than complete. In probectl's control plane this is wired from
  `PROBECTL_AI_MAX_EVIDENCE`.
- **`WithTimeout`** (default `30s`) wraps every query in a context deadline, so one
  pathological query can't hang a request or pin a store.

These are the floor. Higher layers add their own limits on top (the RCA analyzer
caps how many *evidence items* it gathers; the API adds a per-tenant fairness
budget — see `docs/fairness.md`).

## Sources: the seams to the real stores

The engine doesn't know how to talk to Prometheus or ClickHouse directly. It talks
to four small interfaces (`internal/ai/source.go`), and the control plane plugs in
the real implementations:

```go
type MetricsSource  interface { QueryMetrics(ctx, tenant, sel, range, limit) ... }
type EventsSource   interface { QueryEvents(ctx, tenant, sel, range, limit) ... }
type EntitiesSource interface { QueryEntities(ctx, tenant, sel, limit) ... }
type TopologySource interface { QueryTopology(ctx, tenant, query) ... }
```

Every method receives the tenant **the engine chose from the principal** — never a
tenant the caller supplied. A source's job is to scope its read to that tenant and
return rows. `NewTopologySource` adapts the topology graph store; the control
plane backs the entities source with the incident store and the events source with
change events. If a deployment hasn't wired a given store, that domain simply isn't
registered, and a query for it returns `ErrNoSource` — which `Correlate` treats as
"skip this plane," so a small deployment degrades gracefully instead of erroring.

## Why it's built this way (and what it deliberately isn't)

- **Tenant-first, by construction, not by convention.** The biggest possible
  failure in a multi-tenant platform is cross-tenant leakage. Putting the tenant on
  the principal and *omitting it from the query type* removes an entire class of
  bugs: you can't forget a check that isn't a check, and you can't fuzz a field
  that doesn't exist.
- **One boundary, many callers.** API, RCA, and MCP share this engine so the
  isolation rule lives in exactly one place. A new feature that reads telemetry
  inherits tenant-then-RBAC for free instead of re-implementing (and possibly
  mis-implementing) it.
- **It is a read/query layer, not the brain.** This layer does not call any model,
  write data, rank evidence, or decide what a question "means." It returns scoped
  rows. The natural-language understanding, planning, and synthesis live one layer
  up in the RCA analyzer (`docs/ai-rca.md`); the model there gets *only* what this
  layer already scoped, and never gets tools to issue its own queries.

## See also

- `docs/ai-rca.md` — the root-cause analyzer built on this engine.
- `docs/mcp.md` — the MCP server, which reaches data through this same engine.
- `docs/fairness.md` — the per-tenant query-cost budget layered on top.
