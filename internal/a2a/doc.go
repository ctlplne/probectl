// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package a2a is the control-plane broker for agent-to-agent measurement
// sessions (S8). It assigns roles (one agent responds, the other initiates),
// rendezvouses the responder's listen endpoint to the initiator, and hands each
// agent its task when it polls. All state is tenant-scoped: an agent only ever
// receives tasks queued for its own (tenant, agent) identity, and only a
// session's responder — in the session's tenant — may report an endpoint, so a
// session can never cross a tenant boundary (CLAUDE.md §7 guardrail 1).
//
// State is in-memory; pair and mesh sessions start through the tenant-scoped,
// RBAC-gated, audited A2A API/CLI. A2A deliberately stays outside the agent's
// local scheduled-canary registry because safely forming one assignment needs
// both tenant-bound peers and an ordered responder rendezvous. See
// docs/adr/a2a-broker-coordination.md.
package a2a
