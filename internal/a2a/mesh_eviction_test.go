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
		// Results are keyed BY TENANT in production (recordResult appends to
		// m.results[tenantID]); the earlier per-session-id fixture mis-modeled
		// this and masked that eviction's result pruning was a no-op.
		m.results["tenant-a"] = append(m.results["tenant-a"], MeshResult{SessionID: id, TenantID: "tenant-a"})
		m.byTenant["tenant-a"] = append(m.byTenant["tenant-a"], id)
	}
	m.evictOldestLocked("tenant-a")
	retained := len(m.byTenant["tenant-a"])
	sessions := len(m.sessions)
	results := len(m.results["tenant-a"])
	// The surviving ids must be the NEWEST (FIFO eviction drops the front).
	newestKept := m.byTenant["tenant-a"][0]
	oldestResultKept := m.results["tenant-a"][0].SessionID
	m.mu.Unlock()

	if retained != maxMeshSessionsPerTenant {
		t.Fatalf("retained %d sessions, want exactly %d", retained, maxMeshSessionsPerTenant)
	}
	if sessions != maxMeshSessionsPerTenant || results != maxMeshSessionsPerTenant {
		t.Fatalf("maps not trimmed: sessions=%d results=%d, want %d each (result pruning is keyed by tenant)", sessions, results, maxMeshSessionsPerTenant)
	}
	want := fmt.Sprintf("sess-%06d", over-maxMeshSessionsPerTenant)
	if newestKept != want {
		t.Fatalf("oldest surviving id = %q, want %q (FIFO eviction drops the oldest)", newestKept, want)
	}
	if oldestResultKept != want {
		t.Fatalf("oldest surviving result = %q, want %q (results for evicted sessions must be pruned)", oldestResultKept, want)
	}
}
