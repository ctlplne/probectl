// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"fmt"
	"testing"
)

// INJ-06: mesh sessions have no TTL, so repeated requests once accumulated
// session + result state forever (leak → OOM). evictOldestLocked bounds a
// tenant's retained sessions FIFO. Exercised directly (no broker) so the bound
// is asserted without creating tens of thousands of real sessions.
func TestMeshEvictsOldestBeyondPerTenantCap(t *testing.T) {
	m := NewMeshScheduler(NewBroker())
	const over = maxMeshSessionsPerTenant + 5000

	m.mu.Lock()
	for i := 0; i < over; i++ {
		id := fmt.Sprintf("sess-%06d", i)
		m.sessions[id] = MeshSession{SessionID: id, TenantID: "tenant-a"}
		m.results[id] = []MeshResult{{SessionID: id}}
		m.byTenant["tenant-a"] = append(m.byTenant["tenant-a"], id)
	}
	m.evictOldestLocked("tenant-a")
	retained := len(m.byTenant["tenant-a"])
	sessions := len(m.sessions)
	results := len(m.results)
	// The surviving ids must be the NEWEST (FIFO eviction drops the front).
	newestKept := m.byTenant["tenant-a"][0]
	m.mu.Unlock()

	if retained != maxMeshSessionsPerTenant {
		t.Fatalf("retained %d sessions, want exactly %d", retained, maxMeshSessionsPerTenant)
	}
	if sessions != maxMeshSessionsPerTenant || results != maxMeshSessionsPerTenant {
		t.Fatalf("maps not trimmed: sessions=%d results=%d, want %d each", sessions, results, maxMeshSessionsPerTenant)
	}
	if want := fmt.Sprintf("sess-%06d", over-maxMeshSessionsPerTenant); newestKept != want {
		t.Fatalf("oldest surviving id = %q, want %q (FIFO eviction drops the oldest)", newestKept, want)
	}
}
