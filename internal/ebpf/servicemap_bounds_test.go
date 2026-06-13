// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"testing"
	"time"
)

func flowAt(src, dst string, port uint32, at time.Time) Flow {
	return Flow{
		TenantID: "t", Transport: "tcp", Bytes: 100, Packets: 1, Observed: at,
		Source:      Endpoint{Workload: src},
		Destination: Endpoint{Workload: dst, Port: port},
	}
}

// SCALE-003: the service map caps its live edge set (evicting least-recently-
// seen) and prunes idle edges, so a privileged agent on a busy host can't grow
// it without bound — with eviction counted, never silent.
func TestServiceMapBounds(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	// Cap of 3: a 5th distinct edge evicts the oldest; Len stays <= 3.
	m := NewServiceMap()
	m.SetBounds(3, 0)
	for i := 0; i < 5; i++ {
		m.Observe(flowAt("web", "dst", uint32(1000+i), base.Add(time.Duration(i)*time.Minute)))
	}
	if m.Len() != 3 {
		t.Fatalf("edge cap not enforced: Len=%d, want 3", m.Len())
	}
	if m.Evicted() != 2 {
		t.Fatalf("evicted=%d, want 2", m.Evicted())
	}

	// Idle-TTL prune: an edge not seen within the window is dropped.
	m2 := NewServiceMap()
	m2.SetBounds(0, 10*time.Minute)
	m2.Observe(flowAt("a", "b", 80, base.Add(-30*time.Minute))) // stale
	m2.Observe(flowAt("c", "d", 80, base.Add(-1*time.Minute)))  // fresh
	if pruned := m2.Prune(base); pruned != 1 {
		t.Fatalf("prune=%d, want 1", pruned)
	}
	if m2.Len() != 1 {
		t.Fatalf("after prune Len=%d, want 1", m2.Len())
	}
}
