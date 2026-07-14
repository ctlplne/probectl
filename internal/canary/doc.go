// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package canary defines the Canary plugin interface — the load-bearing
// extension point for every probectl measurement type — together with the
// Result/Spec/Config shapes and a Registry of compiled-in plugin factories
// (S5). A no-op plugin is included to exercise the agent runtime.
//
// The real probes (icmp/tcp/udp/http/dns, ...) are added from S7 by registering
// their factories. A probe failure is a Result with Success=false, never a
// returned error or a panic (CLAUDE.md §6).
package canary
