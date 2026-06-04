// Package mcp is probectl's Model Context Protocol server (S25, F14): an AI-native,
// composable interface that exposes probectl's read tools to MCP clients (e.g.
// Claude Desktop) over two transports — stdio (local) and HTTP (network, TLS +
// bearer-authenticated).
//
// It is a thin, dependency-free JSON-RPC 2.0 server. Every call enforces the
// two-level security boundary: the TENANT first (an MCP caller is bound to a
// single tenant), then the caller's RBAC. tools/list returns only the tools the
// caller may use, and tools/call re-checks the tool's permission and then runs
// through the tenant-scoped backend (the S23 query layer + stores) — so a tool
// can never return another tenant's data or data outside the caller's scope.
//
// The tools here are READ-ONLY (CLAUDE.md §7 guardrail 8 — no action tools);
// write/remediation tools are deferred to S-EE5 as proposal-only. Tool calls are
// rate-limited per tenant. The catalog + JSON schemas + auth model are the stable
// contract other sprints append tools to.
package mcp
