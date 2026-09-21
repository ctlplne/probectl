// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package canary defines the Canary plugin interface — the load-bearing
// extension point for every probectl measurement type — together with the
// Result/Spec/Config shapes and a Registry of compiled-in plugin factories
// (S5). A no-op plugin is included to exercise the agent runtime.
//
// The real probes (icmp/tcp/udp/http/dns, ...) are added from S7 by registering
// their factories. A probe failure is a Result with Success=false, never a
// returned error or a panic (CONTRIBUTING.md).
package canary
