# Tenancy & hard isolation

## What it is

A **tenant** is one isolated customer or organization sharing a single probectl
deployment. Tenancy is the rule that one tenant can *never* read another tenant's
data — and in probectl, that rule is the **outermost** boundary, checked before
anything else, including roles and permissions.

The everyday analogy is an apartment building. Many residents share one structure
— the foundation, the plumbing, the lobby — but every unit has its own hard lock,
and the building manager's master key opens the boiler room, never anyone's
apartment. probectl gives you three layouts on that theme:

- **Pooled** — everyone shares the same tables, databases, and message channels,
  told apart by a tenant identifier on every record. Cheapest and densest. The
  default.
- **Siloed** — each tenant gets its own database schema, its own telemetry
  database, its own message channels, and its own storage namespace. The strongest
  separation.
- **Hybrid** — a shared (pooled) control plane, but a *per-tenant* database for
  the high-volume traffic telemetry. A middle ground.

As housing: pooled is the apartment building, siloed is a street of detached
houses, hybrid is an apartment with a detached private garage for the bulky
stuff. You choose per deployment *and* per tenant — one install can run most
tenants pooled and a few high-compliance ones siloed.

Three terms recur ([glossary](../glossary.md)): **RLS** (Row-Level Security) is a
database feature that filters every query to a single tenant's rows inside the
database engine itself; a **partition key** is the column the telemetry store uses
to keep each tenant's rows physically grouped; the **bus** is the message pipe
between agents and the control plane, and its named channels are **topics**.

## Why it exists

Most applications enforce a tenant boundary in handler code — a "where tenant
equals this one" clause on every query. That works right up until the day someone
forgets the clause, a crafted input slips through, or a bug routes a query to the
wrong place. probectl treats that day as **inevitable** and pushes the boundary
*down into the storage layer itself*, so the data store refuses to hand over
another tenant's rows even when the application code above it is wrong.

This is **defense-in-depth**: stacked, independent layers, each built on the
assumption that the layer above it has already failed. Cross-tenant data leakage
is the single highest-severity failure a multi-tenant observability platform can
have, so it gets the strongest, lowest, most paranoid defense — not a polite
filter in the application.

A second reason is the **noisy neighbor**. In a pooled deployment many tenants
share one pipeline, one set of stores, one query engine. Without protection, a
single tenant dumping a firehose of results or hammering the query interface
could slow everyone else down. Fairness exists to make sure isolation is not just
about *secrecy* (you can't read my data) but also about *availability* (you can't
starve me of the shared platform).

## How it works

### The boundary lives in the storage layer

Every tenant-owned record carries a non-null tenant identifier from its first
day. In a pooled deployment, the durable-state database enforces isolation with
**forced Row-Level Security**: a policy attached to each table silently appends a
tenant filter to *every* statement, inside the database engine, below any
application code. The effect is striking — even a predicate-free
`SELECT * FROM incidents` returns only the calling tenant's rows. Picture a
wristband at a venue: the connection is banded with one tenant at the door, and
the database hands out only rows wearing the matching band, no matter how broad
the question asked upstairs.

Three things make that more than a suggestion:

- **The application role cannot bypass the policy.** probectl connects as a role
  that is explicitly *not* a superuser and explicitly *cannot* bypass row
  security. If it connected as a privileged role, every policy would be
  decorative. It does not.
- **Even the table owner is bound.** The tables use *forced* row security, which
  closes the subtle gap where a table's owner is normally exempt from its own
  policies.
- **A misconfigured deployment refuses to serve.** Before the control plane
  accepts any traffic, it verifies — inside a real tenant-scoped transaction —
  that the role is non-privileged and that *every* table carrying a tenant
  identifier has row security forced on. If any check fails, that is a fatal
  startup error. The control plane will not start with a broken boundary.

The high-volume telemetry store gets a layered defense too. Every query leads
with a tenant filter and an unscoped query is refused in code; every value travels
as a server-bound parameter (so a tenant identifier shaped like an injection
attack arrives as *data*, never as syntax); and a database-level row policy
constrains any per-tenant credential used directly against the store. Where one
shared service credential must remain powerful for ingest and maintenance, an
opt-in reader split takes that account off the read path entirely, so a
compromised query path that omits the filter still cannot cross tenants.

### Physical separation stacks on top, never instead

The key idea for siloed and hybrid: **physical separation is layered *on top of*
the pooled scoping, never *instead of* it.** A siloed schema still re-creates the
isolation policies, every transaction still binds the tenant, bus messages stay
tenant-keyed, and every read is still tenant-scoped. So even if routing somehow
sent a query to the wrong silo, the query would return *nothing* rather than
another tenant's rows — walking into the wrong house still leaves you facing a
locked safe whose key you don't hold. The defenses stack; they don't replace each
other.

Routing **fails closed everywhere, including on the bus.** A siloed tenant is
never silently downgraded to the shared stores, and a pooled query can never reach
a siloed tenant's stores. If a result arrives and its siloed tenant's channel
cannot be resolved, the control plane drops that result with a loud error rather
than publishing it onto the shared channel — a siloed tenant's telemetry must
never silently ride the shared lane. Availability comes from the *agent's*
store-and-forward buffer retrying delivery, not from a fallback that risks
mis-routing.

### Fairness: bounding the noisy neighbor

Three mechanisms keep a pooled deployment safe, and enforcement is in *every*
edition — protecting the shared platform is the platform's own job, not a paid
add-on. (A single-tenant deployment has no neighbors, so it never trips anything.)

- **Ingest rate bounds.** A *token bucket* per tenant wraps the ingest consumers.
  Picture a bucket under a steadily dripping tap: the drip is the permitted rate,
  the bucket size is the burst allowance, and an empty bucket means the unit is
  *shed* — turned away at the door before any expensive work happens. The check is
  cheap and happens before decode-enrich-store, so an over-rate burst never stalls
  the shared pipeline.
- **Query-cost guards.** Per tenant: how many queries may be in flight at once,
  and how many per minute. An over-budget tenant gets a clear `429` "too many
  requests" with a retry-after, instead of a slow platform for everyone.
- **Accounting.** Every shed unit and rejected query is counted per tenant and
  visible to that tenant directly — debugging a fairness dispute never requires
  the operator's word.

Fairness bounds *rates*, never lifetime totals: a legitimately busy tenant running
under its sustained budget is never rejected, and a shed tenant recovers the
instant its burst window passes — there is no penalty box.

## Use it

**Read your own fairness posture and accounting** (your effective policy plus
admitted/shed/rejected counts):

```sh
curl https://control.example/v1/fairness
```

What you should observe: your effective limits and live counters. `admitted`
climbs with normal traffic; `shed` is non-zero only if you exceeded your ingest
rate; `rejected` is non-zero only if you exceeded a query budget. A response of
`{"enforcing": false}` means the deployment is running with the fairness gate
unwired.

**See it work the other way — the cross-tenant test you can reason about.** The
guarantee is that a query naming another tenant's data returns nothing, not an
error full of hints. If you query an incident or result that belongs to a
different tenant than your session, you get an empty result, because the database
filtered it out before your code ran:

```sh
curl https://control.example/v1/results/latest
```

What you should observe: only your own tenant's results, ever — there is no
parameter you can add to widen that scope, because the boundary is below the API.

**Choose an isolation model when provisioning a tenant** (a provider/operator
action; siloed and hybrid require the licensed tier):

```json
{
  "slug": "acme",
  "name": "Acme Corp",
  "isolation_model": "siloed",
  "residency": "eu"
}
```

What you should observe: the isolated stores are created *before* the call
returns — a siloed tenant never exists without its silo. A residency pin places
that tenant's telemetry databases on the named regional data plane. Offboarding
later tears those isolated stores down cleanly.

**Inspect the effective posture from inside the tenant:**

```sh
probectl isolation status
curl https://control.example/v1/isolation/status
```

What you should observe: the response names the caller tenant's effective model
(`pooled`, `siloed`, or `hybrid`), the sanitized Postgres RLS health bit, the bus
lane namespace used by that tenant, and the tenant's own silo-routing targets.
It does not list tenants, counts by model, registry rows, data-plane URLs, or raw
router/RLS errors that could reveal another tenant's identifiers.

## Pitfalls & limits

- **Pooled is shared infrastructure, hardened — not physical separation.** It is
  the right default and it holds, but if your compliance posture demands physical
  separation per customer, choose siloed or hybrid. Pooled stakes everything on
  the storage-layer enforcement (which is exactly why that enforcement is so
  paranoid).
- **Siloing has an operational cost.** Schema changes are written once and then
  brought to every silo separately. probectl does this automatically at startup
  (creating missing tables and columns) and the lag is always *visible*, never
  silent — but a destructive "contract" change across many silos is an operator
  step.
- **Residency pins telemetry, not everything — and a residency claim you cannot
  back up is a liability.** A siloed or hybrid tenant's telemetry databases are
  created on and routed to the chosen region. The shared control-plane state, the
  metrics store, the object store namespace, and the message brokers are *not*
  region-pinned today. Do not claim otherwise. For a strict tenant, run siloed
  with the stores confined to the permitted region.
- **The object-store split is a namespace today.** A siloed tenant's artifacts
  move under a per-tenant key namespace on the same backend — strong logical
  separation, but not a separate storage system. Stated plainly so it is never a
  surprise.
- **The fairness query guards default to unlimited; the ingest bounds do not.**
  The shipped defaults bound ingest rates out of the box (the thing one tenant is
  most likely to wreck) but leave the two query guards unlimited until you set
  them. The device-metrics and OTLP-series rates *are* enforced per tenant (their
  own token buckets), but their *values* are deployment defaults with no per-tenant
  override today — the per-tenant override store covers the other meters, not
  these two.
- **Fairness is protection, not billing or hard isolation.** It bounds rates on
  the shared pipeline. Counting usage is a separate concern, and hard separation
  is what siloed mode is for.
- **When in doubt, the system fails closed.** A missing or unprovable tenant on
  any path returns nothing rather than guessing. Empty results are a feature here,
  not a bug.

## Reference

- **Isolation models:** pooled (shared stores, tenant identifier enforced at the
  storage layer; the default), siloed (per-tenant schema / telemetry database /
  topics / object namespace), hybrid (pooled control plane, per-tenant telemetry
  database plus a per-tenant message-bus topic namespace and a per-tenant
  object-store key namespace). Selectable per deployment and per tenant; siloed and
  hybrid require the licensed tier, pooled always works.
- **Storage-layer enforcement:** forced Row-Level Security in the durable-state
  database (the application role cannot bypass it; even the table owner is bound;
  a broken posture is a fatal startup error); leading tenant filter plus
  server-bound parameters plus an optional reader split in the telemetry store; a
  standing cross-tenant isolation test gate.
- **Fail-closed routing:** a routing error fails the operation; siloed telemetry
  never rides the shared channel; the agent's buffer provides availability, not a
  fallback.
- **Fairness:** per-tenant ingest token buckets and query-cost guards; an
  over-budget query returns `429` with a retry-after; per-tenant accounting at
  `GET /v1/fairness`; enforcement is core in every edition.
- **Residency:** a siloed/hybrid tenant's telemetry databases pin to a named
  regional data plane; control-plane state, metrics, object store, and bus are not
  pinned today.
- **Related capabilities (separate pages):** the Provider / MSP plane (operator
  privilege model, break-glass, white-label, per-tenant keys); Running probectl in
  production (governance, erasure, residency in multi-region).

**Covers:** F50, F52, F57
