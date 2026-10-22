// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package agenttransport is the control-plane side of the agent <-> control-plane
// gRPC transport (S4). Every connection is mTLS (S3 crypto.ServerMTLSConfig);
// non-mTLS clients are rejected at the TLS layer. The caller's tenant and agent
// id are derived from the verified client certificate's SPIFFE identity
// (spiffe://probectl/tenant/<t>/agent/<a>), never trusted from the request body, so
// an agent is bound to exactly one tenant and everything it does is
// tenant-attributable at the source (F50).
//
// It implements Register, Attest, Heartbeat, StreamResults (agent->server),
// the agent-to-agent coordination pair, and FetchTestBundle: the agent's PULL
// of its tenant's signed central test set (G9, docs/adr/central-test-distribution.md),
// served for the certificate's tenant only and verified by the agent before it
// runs anything. StreamConfig is an EXPLICIT DENY kept for wire compatibility
// (U-044/ARCH-003): config push is deliberately not a shipped capability —
// every agent setting stays local, and there is no remote control channel (see
// docs/adr/config-push.md). Registration persists to the agents registry via
// internal/store.
package agenttransport
