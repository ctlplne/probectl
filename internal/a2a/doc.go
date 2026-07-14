// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package a2a is the control-plane broker for agent-to-agent measurement
// sessions (S8). It assigns roles (one agent responds, the other initiates),
// rendezvouses the responder's listen endpoint to the initiator, and hands each
// agent its task when it polls. All state is tenant-scoped: an agent only ever
// receives tasks queued for its own (tenant, agent) identity, and only a
// session's responder — in the session's tenant — may report an endpoint, so a
// session can never cross a tenant boundary (CLAUDE.md §7 guardrail 1).
//
// State is in-memory for S8; the trigger to start a session is wired to the
// test/probe API in a later sprint.
package a2a
