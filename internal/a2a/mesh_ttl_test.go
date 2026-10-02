// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"testing"
	"time"
)

// TestMeshSchedulerExpiresSessionsAfterTTL is the AI-01 regression for retained
// mesh state: sessions were only FIFO-capped, never released on a TTL, so state
// for agents that never poll lingered. A tenant's sessions older than
// meshSessionTTL must be swept on its next StartMesh.
func TestMeshSchedulerExpiresSessionsAfterTTL(t *testing.T) {
	m := NewMeshScheduler(NewBroker())
	clock := time.Unix(1_700_000_000, 0).UTC()
	m.now = func() time.Time { return clock }
	// The broker shares nothing with the mesh clock here; give it a fixed clock
	// too so its own gc is deterministic.
	m.broker.now = func() time.Time { return clock }

	first := []SiteAgent{{AgentID: "ghost-a", Site: "s1"}, {AgentID: "ghost-b", Site: "s2"}}
	if _, err := m.StartMesh("tenant-a", first, "udp", 1); err != nil {
		t.Fatalf("first StartMesh: %v", err)
	}
	m.mu.Lock()
	n1 := len(m.byTenant["tenant-a"])
	m.mu.Unlock()
	if n1 != 2 { // 2 sites => 2 directed sessions
		t.Fatalf("after first mesh, retained sessions = %d, want 2", n1)
	}

	// Advance past the mesh TTL (15m) and run another mesh; the first mesh's
	// sessions (whose agents never polled) must be gone, not merely FIFO-retained.
	// A literal is used (not meshSessionTTL) so this regression also compiles and
	// asserts-red against the pre-fix tree, which has no such constant.
	clock = clock.Add(16 * time.Minute)
	second := []SiteAgent{{AgentID: "ghost-c", Site: "s3"}, {AgentID: "ghost-d", Site: "s4"}}
	if _, err := m.StartMesh("tenant-a", second, "udp", 1); err != nil {
		t.Fatalf("second StartMesh: %v", err)
	}

	m.mu.Lock()
	retained := len(m.byTenant["tenant-a"])
	total := len(m.sessions)
	m.mu.Unlock()
	if retained != 2 {
		t.Fatalf("after TTL, retained sessions for tenant-a = %d, want only the 2 fresh ones "+
			"(stale never-polled mesh state was not expired — AI-01)", retained)
	}
	if total != 2 {
		t.Fatalf("global session map = %d, want 2 (expired sessions not released)", total)
	}
}
