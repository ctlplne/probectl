# ADR: BGP collector ingestion is per tenant (shared fan-out is a recorded boundary)

**Status:** Accepted (2026-08-01, Foundation-Loop T-20082ca1). Supersedes the
contract wording that described BGP collector data as "ingested once and
scoped per tenant" — that described a fan-out that was never built.

> This is the **decision record** for how external BGP collector data enters
> a multi-tenant deployment. The operator-facing description lives in
> `docs/bgp.md`; the schema contract carries a matching comment in
> `proto/probectl/bgp/v1/bgp.proto`.

## The plain version

Every monitored tenant gets its own analyzer subprocess, and that subprocess
consumes its own copy of the external feeds. Twenty tenants monitoring BGP
means twenty RIS Live websocket consumers and twenty sets of supplied MRT
artifacts — not one shared consumer with twenty scoped outputs.

## Context

- `internal/bgp.NewAnalyzerRunner` requires a `TenantID` and supervises one
  subprocess per tenant; `analyzer/probectl_analyzer/config.py` refuses a
  configuration without `tenant_id`. The tenant binding is the process
  boundary itself.
- The open-data/threat plane genuinely does ingest once and scope per tenant
  (`internal/opendata`); the old blanket sentence in CLAUDE.md §3 extended
  that claim to every external feed, which the BGP plane never implemented.
- This is the one plane whose data is entirely external, so the ingestion
  model is a real resource-scaling question for MSP deployments.

## Decision

Per-tenant ingestion is the accepted model at the current scale envelope.

Why: binding the tenant at the process boundary means the analyzer holds no
cross-tenant state at all — there is nothing to scope, leak, or fence inside
it, and guardrail 1 is enforced by construction (the subprocess cannot emit
for a tenant it was not started for; the Go bridge refuses events without a
tenant). A shared consumer would move that boundary into code that must then
be audited for it.

Costs, stated honestly: N tenants cost N feed consumers — N RIS Live
websocket connections against RIPE's public service, N times the parse CPU,
and N times any supplied-MRT processing. Feed volume is modest per consumer
and MRT artifacts are operator-supplied files, so the practical ceiling is
the RIS Live connection count and duplicate parse cost.

## Scaling boundary (the trigger, so this is not re-litigated ad hoc)

Build the shared ingest-once fan-out seam — one collector consumer,
per-tenant scoping applied at publish onto `probectl.bgp.events` — when a
deployment needs **more than ~25 concurrently monitored BGP tenants**, or
when RIS Live connection pressure (upstream throttling/disconnects caused by
parallel connections from one deployment) is observed in practice, whichever
comes first. The seam belongs in the Go bridge (`internal/bgp`), keeping the
Python analyzer single-tenant; scoping at publish must preserve the existing
fail-closed no-tenant behavior.

## Invariants preserved (each bound to an existing check)

- An event with no tenant is refused by the bridge — `go test ./internal/bgp
  -run Tenant` and the pipeline verification lane.
- BMP peers derive their tenant from the verified SPIFFE client certificate,
  never the payload — BMP listener tests (`internal/bgp`).
- Storage-layer tenant scoping on everything published —
  `make test-isolation`.

## Consequences

- The proto file comment, CLAUDE.md §3, `docs/architecture.md`'s diagram edge
  and `docs/bgp.md` now state per-tenant ingestion; the claim register binds
  the ingestion-model phrasing so contract text and code cannot drift apart
  silently again.
- Sizing guidance for MSPs belongs with the ~25-tenant trigger above; until
  the fan-out exists, BGP monitoring cost scales linearly with tenants.
