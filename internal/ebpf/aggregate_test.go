// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import "testing"

func TestAggregatorDrainAndDrops(t *testing.T) {
	a := NewAggregator()
	flow := Flow{TenantID: "t1", Source: Endpoint{Workload: "api"}, Destination: Endpoint{Workload: "db", Port: 443}, Transport: "tcp"}
	a.Observe(flow)
	a.Observe(flow)
	a.RecordDrops(3)
	a.RecordDropStats(DropStats{L4RingBufferFull: 2, L7ActiveReadFailures: 1, L7ScopeSyncFailures: 1})

	flows, edges := a.Drain()
	if len(flows) != 2 {
		t.Fatalf("drained flows = %d, want 2", len(flows))
	}
	if len(edges) != 1 || edges[0].Connections != 2 {
		t.Fatalf("edges = %+v, want one edge with conns=2", edges)
	}

	// Drain clears pending flows but the service map is cumulative.
	flows2, edges2 := a.Drain()
	if len(flows2) != 0 {
		t.Errorf("second drain flows = %d, want 0", len(flows2))
	}
	if len(edges2) != 1 {
		t.Errorf("service map should persist across drains, got %d edges", len(edges2))
	}

	if st := a.Stats(); st.Observed != 2 || st.Dropped != 7 || st.Edges != 1 || st.Other != 3 || st.L4RingBufferFull != 2 || st.L7ActiveReadFailures != 1 || st.L7ScopeSyncFailures != 1 {
		t.Errorf("stats = %+v, want observed=2 dropped=7 edges=1 other=3 l4_ring=2 active_reads=1 scope_sync=1", st)
	}
}
