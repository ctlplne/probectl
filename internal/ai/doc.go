// Package ai is probectl's AI layer. This sprint (S23) implements the unified
// semantic query layer — one RBAC-aware abstraction over the stores (metrics,
// events/flows, entities, and the topology graph) that the API, the AI/RCA layer
// (S24), and the MCP server (S25) all use.
//
// It is THE security boundary for AI and MCP: every query enforces the TENANT
// boundary FIRST, then the caller's RBAC, at this layer — never relying on a
// model to self-censor. The tenant is taken from the authenticated principal,
// never from the query, so a query is incapable of crossing tenants by
// construction (it inherits the S2 store-level scoping). CLAUDE.md §7
// guardrails 1 (tenant isolation) and 5 (RBAC on every path, including AI/MCP).
package ai
