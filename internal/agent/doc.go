// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package agent is the probectl agent runtime (S5): a plugin host that runs
// compiled-in canaries on a schedule into a disk-backed, bounded store-and-forward
// buffer, plus a forwarder that registers, heartbeats, and drains the buffer to
// the control plane over mTLS (S4), reconnecting with backoff.
//
// Probing runs independently of connectivity, so results accumulate during an
// outage and drain on reconnect (at-least-once). The agent is tenant-bound: its
// identity comes from its client certificate's SPIFFE id, and every result it
// buffers/emits is stamped with that tenant + agent id (F50). It holds no database
// connection — it is a thin, dependency-light client.
//
// A2A measurement is the deliberate exception to local canary scheduling: an
// opted-in Coordinator polls for control-plane-brokered two-agent tasks and
// writes their results into the same buffer. It is not a registered Canary
// plugin; see docs/adr/a2a-broker-coordination.md.
package agent
