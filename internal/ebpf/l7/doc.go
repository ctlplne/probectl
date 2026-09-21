// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package l7 parses application-protocol calls (HTTP/1.1, HTTP/2, gRPC, DNS,
// Kafka) from the plaintext byte streams the eBPF agent captures (S21) — via
// TLS-library uprobes (plaintext-before-encryption) or directly from sockets.
//
// Each Parser consumes a single connection's ordered DataEvents (one direction
// at a time) and emits Calls with method / resource / status / latency, which
// the agent rolls up onto service edges (S20). A per-connection Tracker detects
// the protocol from the first request bytes (with a destination-port hint) and
// delegates to the matching parser.
//
// The package is pure Go and kernel-independent: in production it is fed by the
// capture layer; in tests it is fed byte fixtures. It is observe-only — it only
// reads captured plaintext and never alters traffic (CLAUDE.md §7 guardrail 8).
package l7
