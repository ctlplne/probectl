// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"errors"
	"testing"
)

// TestBrokerBoundsPendingPerTenant is the INJ-06 within-TTL backstop: age-out
// reclaims unpolled tasks only after the TTL, so a burst of mesh requests naming
// never-polling agent ids must still be bounded in the window before they age
// out. The broker refuses new sessions once a tenant is at maxPendingPerTenant,
// fail-closed and per-tenant (one tenant's flood never locks another).
func TestBrokerBoundsPendingPerTenant(t *testing.T) {
	b := NewBroker()

	// Pin tenant-a at the cap without the O(n^2) cost of enqueuing one at a time
	// (gcLocked runs on every call); the cap check reads this counter.
	b.mu.Lock()
	b.pendingByTenant["tenant-a"] = maxPendingPerTenant
	b.mu.Unlock()

	if _, err := b.StartSession("tenant-a", "r", "i", "udp", 1); !errors.Is(err, ErrPendingFull) {
		t.Fatalf("StartSession at the per-tenant cap = %v, want ErrPendingFull", err)
	}
	// A different tenant is never locked out by tenant-a's flood.
	if _, err := b.StartSession("tenant-b", "r", "i", "udp", 1); err != nil {
		t.Fatalf("a second tenant must not be blocked by tenant-a's backlog: %v", err)
	}
	// Once tenant-a's queue drains (polled or aged out), it can enqueue again.
	b.mu.Lock()
	b.pendingByTenant["tenant-a"] = 0
	b.mu.Unlock()
	if _, err := b.StartSession("tenant-a", "r2", "i2", "udp", 1); err != nil {
		t.Fatalf("tenant-a stays locked after its backlog drained: %v", err)
	}

	// The mesh scheduler refuses up front, before the O(n^2) loop, too.
	m := NewMeshScheduler(b)
	b.mu.Lock()
	b.pendingByTenant["tenant-c"] = maxPendingPerTenant
	b.mu.Unlock()
	_, err := m.StartMesh("tenant-c", []SiteAgent{{AgentID: "a1", Site: "s1"}, {AgentID: "a2", Site: "s2"}}, "udp", 1)
	if !errors.Is(err, ErrPendingFull) {
		t.Fatalf("StartMesh at the per-tenant cap = %v, want it wrapped around ErrPendingFull", err)
	}
}
