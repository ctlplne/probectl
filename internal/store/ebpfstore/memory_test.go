// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpfstore

import (
	"context"
	"testing"
	"time"
)

// ARCH-008: the eBPF aggregate store persists tenant-scoped edges, dedups a
// re-observed identical window (ReplacingMergeTree discipline), ranks by bytes,
// isolates tenants, and erases verifiably.
func TestMemoryStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	w := time.Unix(1_700_000_000, 0).UTC()

	mustInsert := func(edges ...Edge) {
		if err := s.Insert(ctx, edges); err != nil {
			t.Fatal(err)
		}
	}
	mustInsert(
		Edge{TenantID: "t-a", AgentID: "n1", WindowStart: w, SrcWorkload: "web", DstWorkload: "db", DstPort: 5432, Bytes: 1000, Packets: 10, Connections: 2},
		Edge{TenantID: "t-a", AgentID: "n1", WindowStart: w, SrcWorkload: "web", DstWorkload: "cache", DstPort: 6379, Bytes: 5000, Packets: 50, Connections: 5},
		Edge{TenantID: "t-b", AgentID: "n9", WindowStart: w, SrcWorkload: "x", DstWorkload: "y", DstPort: 80, Bytes: 9999, Packets: 1, Connections: 1},
	)
	// Re-observe the web→db edge with updated counts: must REPLACE, not append.
	mustInsert(Edge{TenantID: "t-a", AgentID: "n1", WindowStart: w, SrcWorkload: "web", DstWorkload: "db", DstPort: 5432, Bytes: 1200, Packets: 12, Connections: 3})

	top, err := s.TopEdges(ctx, "t-a", EdgeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 2 {
		t.Fatalf("dedup failed: %d edges, want 2", len(top))
	}
	if top[0].DstWorkload != "cache" || top[0].Bytes != 5000 {
		t.Fatalf("ranking wrong: top = %+v", top[0])
	}
	if top[1].Bytes != 1200 {
		t.Fatalf("re-observation did not replace: web→db bytes = %d, want 1200", top[1].Bytes)
	}

	// Tenant isolation: t-a never sees t-b's edge.
	for _, e := range top {
		if e.TenantID != "t-a" {
			t.Fatalf("cross-tenant edge leaked: %+v", e)
		}
	}

	// Unscoped query refused.
	if _, err := s.TopEdges(ctx, "", EdgeQuery{}); err != ErrNoTenant {
		t.Fatalf("unscoped query: err = %v, want ErrNoTenant", err)
	}

	// Verifiable erasure.
	if _, err := s.DeleteTenant(ctx, "t-a"); err != nil {
		t.Fatal(err)
	}
	if top, _ := s.TopEdges(ctx, "t-a", EdgeQuery{}); len(top) != 0 {
		t.Fatalf("erase failed: %d edges remain", len(top))
	}
	if top, _ := s.TopEdges(ctx, "t-b", EdgeQuery{}); len(top) != 1 {
		t.Fatal("erasing t-a affected t-b (isolation broken)")
	}
}
