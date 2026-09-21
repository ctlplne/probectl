// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package ai is probectl's AI layer. This sprint (S23) implements the unified
// semantic query layer — one RBAC-aware abstraction over the stores (metrics,
// events/flows, entities, and the topology graph) that the API, the AI/RCA layer
// (S24), and the MCP server (S25) all use.
//
// It is THE security boundary for AI and MCP: every query enforces the TENANT
// boundary FIRST, then the caller's RBAC, at this layer — never relying on a
// model to self-censor. The tenant is taken from the authenticated principal,
// never from the query, so a query is incapable of crossing tenants by
// construction (it inherits the S2 store-level scoping). docs/guardrails.md
// guardrails 1 (tenant isolation) and 5 (RBAC on every path, including AI/MCP).
package ai
