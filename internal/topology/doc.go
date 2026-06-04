// Package topology is probectl's live, versioned, tenant-scoped network topology
// graph (S30, F40-foundation). It builds a graph — nodes (agents, hops, hosts,
// services, prefixes, ASes) and edges (path adjacencies, eBPF service edges, BGP
// routing) — from the path (S10) and eBPF service-map (S20) planes plus routing
// (S14). Nodes and edges carry validity intervals, so the graph is queryable as
// it was at any past time (e.g. an incident time): the temporal model is designed
// in, not bolted on (S30 watch-out).
//
// The Store interface is the query API the AI semantic-query layer (S23) wraps
// with tenant-then-RBAC scoping, and the adjacency model the dedicated-engine
// migration (S43) later replaces. Every graph is tenant-scoped — this foundation
// never returns another tenant's nodes or edges (CLAUDE.md §7 guardrail 1).
package topology
