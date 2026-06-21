# The unified semantic query layer

## What it is

`internal/ai` is probectl's **one way to read data across the platform**. Two
terms first. A **semantic query** is a question phrased in terms of what the
data *means* — "events about this host in the last hour" — rather than in some
database's own query language (PromQL, SQL, a graph traversal). A **tenant** is
one customer or organization sharing a probectl deployment; keeping tenants
invisible to each other (*tenant isolation*) is the platform's outermost,
highest-severity guarantee. This layer lets every feature ask meaning-level
questions while making cross-tenant answers impossible to even phrase.

The problem it solves: probectl stores each kind of telemetry in a store built
for that shape of data —

- **metrics** (timestamped numbers like latency and loss) live in a
  **time-series DB** — a database specialized for writing and range-reading
  timestamped measurements (Prometheus/VictoriaMetrics);
- **high-cardinality** events and flows live in ClickHouse — *cardinality* is how
  many distinct values a field can take, and flow data (every IP/port/flow
  combination) has millions, which time-series databases handle badly and a
  columnar store like ClickHouse handles well;
- **durable entities** — tests, agents, incidents; records that must survive
  restarts — live in Postgres;
- the live network map lives in the **topology graph**.

Instead of teaching every feature how to talk to four different stores,
everything reads through a single typed engine: `ai.Engine`. Think of it as **one
reference desk in front of four very different archives**: you hand the desk one
request slip, it knows which archive holds what, and everything comes back in one
folder. Nobody browses the stacks directly.

The REST API, the AI root-cause assistant (`docs/ai-rca.md`), and the MCP server
(`docs/mcp.md`; **MCP** is the Model Context Protocol, the standard interface
through which AI tools call external systems) all go through this same engine.
That matters because the engine is also **the security boundary for AI and MCP**
— the one place where "which tenant is asking, and what are they allowed to see?"
is decided, *below* any AI model and *below* handler code. The desk only ever
hands you books from your own building, and only from the sections your badge
opens. You never get to name the building.

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

Reading it: `Domain` names which of the four stores to ask; `Selector` is a set
of key/value filters; `Range` bounds time; `Limit` caps rows; the last three
drive topology traversals — a path from `From` to `To`, or the neighbors of
`NodeID`.

Now notice what is **not** there: a tenant field. There is no way to write
`Query{Tenant: "acme"}`, because the type doesn't have that field. The engine
takes the tenant from the **authenticated caller** instead: every request carries
an `auth.Principal` — a **principal** is the identity (user, token, or agent) the
authentication layer has already verified, including which tenant it belongs to.
So a request — including one a language model helped build, or one assembled from
attacker-controlled text — *cannot even express* "give me another tenant's data."
It's not blocked at runtime; it's impossible to say. The request slip has no
"which building" box: the desk stamps your building on it from your badge.

This is the difference between "we check a tenant parameter" — a check that can
be forgotten, spoofed, or fuzzed (bombarded with crafted inputs until one slips
through) — and "there is no tenant parameter to get wrong."

## Two-level scoping: tenant first, then RBAC

Every read passes two gates, in this order, and both **fail closed** — the
security stance where, when anything is missing or in doubt, the answer is
*nothing* rather than *possibly too much*. **RBAC** (role-based access control)
is permission-by-role: what a caller may read is determined by permissions
attached to their roles. The ordering mirrors the platform-wide rule: tenant
isolation is the outermost boundary, RBAC sits inside it, and neither relies on
a model behaving itself.

**Gate 1 — Tenant (by construction).** `Engine.Query` starts with:

```go
if p == nil || p.TenantID == "" {
    return Result{}, ErrNoTenant
}
```

A caller with no tenant is rejected outright (`ErrNoTenant`). The tenant that
*does* get used is `p.TenantID` from the principal, which the engine passes down
to the store. And the stores are themselves tenant-scoped: the topology adapter
first binds a `TenantStore` with `ForTenant(p.TenantID)`, and the Postgres-backed
sources open a **row-level-security** transaction — **RLS** is a Postgres feature
where the *database itself* filters every row by tenant inside the transaction,
so even a buggy SQL statement cannot see foreign rows. That is **defense in
depth**: two independent fences enforcing the same rule, so a bug in the query
layer still doesn't become a leak.

**Gate 2 — RBAC (per domain).** Each domain needs a read permission, mapped one to
one in `internal/ai/permissions.go`:

| Domain     | Store                                      | Permission        |
| ---------- | ------------------------------------------ | ----------------- |
| `metrics`  | Prometheus / VictoriaMetrics               | `metrics.read`    |
| `events`   | ClickHouse (flows / threat / change / bgp) | `events.read`     |
| `entities` | Postgres (tests / agents / incidents)      | `entities.read`   |
| `topology` | the topology graph                         | `topology.read`   |

A caller missing the permission gets `ErrForbidden` for a single-domain query.
The crucial subtlety is what happens in a *correlation* (the cross-domain join,
described next): domains the caller may not read are **silently skipped**, not
error'd. That's deliberate — a correlation should return everything you *can* see
without leaking the *existence* of what you can't, and without failing the whole
answer because one plane was off-limits. Never a partial leak; never a noisy
"you can't see X."

In the archive picture: your badge first decides which building you're in at all
(tenant); inside it, your role decides which reading rooms unlock (RBAC).

`TestQueryLayerCrossTenantIsolation` (`internal/ai/isolation_test.go`) proves a
query issued as tenant A cannot return tenant B's rows.

## The two operations

The engine exposes exactly two methods (`internal/ai/engine.go`):

- `Engine.Query(ctx, principal, Query)` — a **single-domain** read. Runs the two
  gates, then dispatches to the one store the query names. One question, one
  archive.
- `Engine.Correlate(ctx, principal, subject, TimeRange)` — the **cross-store
  join**. It fans one subject (e.g. a host, an IP, a prefix, a node) across
  *every* domain the caller may read, in a fixed order, and returns a single
  envelope (the result shape below). Each result row is tagged with `_domain` so
  you can tell which store it came from. This is how a question about one entity
  gathers evidence from metrics, events, entities, and topology in one shot —
  "pull everything about this subject from every archive I'm allowed in."

Two operations keep the boundary auditable: every platform read is one of these
two calls, so there are exactly two places scoping could go wrong — and both
share the same gates.

## What comes back: the result envelope

Both methods return one normalized `Result` (`internal/ai/result.go`) — the
**result envelope**, a single standard wrapper every read comes back in, no
matter which store (or how many) answered:

```go
type Result struct {
    Tenant    string   // the caller's tenant — the scope of this result
    Domains   []Domain // which domains actually contributed (provenance)
    Rows      []Row    // Row is map[string]any; in a correlation each carries _domain
    Truncated bool     // a cost guard capped the rows
    Elapsed   time.Duration
}
```

`Tenant` restates the scope the answer was built under. `Domains` is
**provenance** — the record of where an answer came from: it tells you (and the
UI, and the auditor) exactly which planes contributed, useful both for trust and
for spotting "this plane returned nothing." Rows are loosely typed
(`map[string]any`) on purpose, because four very different stores feed into one
shape; the layers above (e.g. the RCA evidence builder) pick out the well-known
keys they care about. `Truncated` says a cost guard clipped the rows; `Elapsed`
says how long the read took. The same labeled folder from the desk every time,
contributing archives listed on the cover.

## Cost guards: LLM-built queries can be expensive

A **cost guard** is a hard, engine-level limit on how much one query may consume
— in rows returned or time spent. It matters here because this layer's callers
include an **LLM** (large language model — the AI that, one layer up, helps turn
a user's question into queries): a model, or a careless caller, can ask for a
lot. Two guards bound every query, set when the engine is constructed
(`NewEngine`, defaults shown):

- **`WithMaxRows`** (default `1000`) caps the rows returned and sets
  `Truncated: true` when it bit, so the caller knows the answer was clipped rather
  than complete. In probectl's control plane (the central server agents report to
  and every client queries) this is wired from `PROBECTL_AI_MAX_EVIDENCE`.
- **`WithTimeout`** (default `30s`) wraps every query in a **context deadline** —
  Go's cancellation mechanism, a timer attached to the request that cancels it and
  all work running downstream when it fires — so one pathological query can't hang
  a request or pin a store.

These are the floor, not the whole budget. Higher layers add their own limits on
top: the RCA analyzer caps how many *evidence items* it gathers, and the API adds
a per-tenant fairness budget so one tenant's heavy questions can't starve
another's — see `docs/fairness.md`.

## Sources: the seams to the real stores

The engine doesn't know how to talk to Prometheus or ClickHouse directly — it
carries no driver code at all. It talks to four small interfaces
(`internal/ai/source.go`) — **seams**, deliberately thin interfaces where one
implementation can be unplugged and another plugged in — and the control plane
plugs in the real implementations:

```go
type MetricsSource  interface { QueryMetrics(ctx, tenant, sel, range, limit) ... }
type EventsSource   interface { QueryEvents(ctx, tenant, sel, range, limit) ... }
type EntitiesSource interface { QueryEntities(ctx, tenant, sel, limit) ... }
type TopologySource interface { QueryTopology(ctx, tenant, query) ... }
```

Every method receives the tenant **the engine chose from the principal** — never
a tenant the caller supplied. A source's job is to scope its read to that tenant
and return rows. Each archive has its own door; the desk just needs every door
to accept the same stamped slip — this tenant, these filters, this window.

Concretely: `NewTopologySource` adapts the topology graph store; the control
plane backs the entities source with the incident store, the metrics source with
the attached TSDB writer, and the events source with the change timeline plus
flow-store summaries. BGP-style routing evidence stays in the event/topology
planes: event rows whose source/kind identifies BGP are labeled `bgp`, and
prefix questions anchor topology reads at `prefix:<cidr>`. If a deployment
hasn't wired a given store, that domain simply isn't registered, and a query for
it returns `ErrNoSource` — which `Correlate` treats as "skip this plane," so a
small deployment degrades gracefully instead of erroring. The seam buys two
things: testability (the cross-tenant isolation test runs against an in-memory
store, no databases needed) and sizing freedom (missing stores degrade; they
don't break).

## Why it's built this way (and what it deliberately isn't)

- **Tenant-first, by construction, not by convention.** The biggest possible
  failure in a multi-tenant platform is cross-tenant leakage. Putting the tenant
  on the principal and *omitting it from the query type* removes an entire class
  of bugs: you can't forget a check that isn't a check, and you can't fuzz a
  field that doesn't exist.
- **One boundary, many callers.** API, RCA, and MCP share this engine so the
  isolation rule lives in exactly one place. A new feature that reads telemetry
  inherits tenant-then-RBAC for free instead of re-implementing (and possibly
  mis-implementing) it.
- **It is a read/query layer, not the brain.** This layer does not call any
  model, write data, rank evidence, or decide what a question "means." It returns
  scoped rows. The natural-language understanding lives one layer up in the RCA
  analyzer (`docs/ai-rca.md`): there, a **query planner** — deterministic
  probectl code, never the model — decides which typed queries a question needs,
  and the model only writes prose over rows this layer already scoped. The model
  is never given tools to issue its own queries.

## See also

- `docs/ai-rca.md` — the root-cause analyzer built on this engine.
- `docs/mcp.md` — the MCP server, which reaches data through this same engine.
- `docs/fairness.md` — the per-tenant query-cost budget layered on top.
