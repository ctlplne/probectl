package pathstore

import (
	"context"
	"testing"

	"github.com/imfeelingtheagi/netctl/internal/path"
)

func samplePath() *path.Path {
	return &path.Path{
		Target: "8.8.8.8", TargetIP: "8.8.8.8", Mode: "icmp", MaxHops: 30, TraceCount: 2, DestinationReached: true,
		Hops: []path.Hop{
			{TTL: 1, Nodes: []path.HopNode{{IP: "10.0.0.1", Sent: 2, Received: 2, RTTAvgMs: 1.2, MPLS: []path.MPLSLabel{{Label: 16001, S: true, TTL: 1}}}}},
			{TTL: 2, Nodes: []path.HopNode{{IP: "8.8.8.8", Sent: 2, Received: 2, RTTAvgMs: 9.5}}},
		},
		Links: []path.Link{{TTL: 1, From: "10.0.0.1", To: "8.8.8.8"}},
	}
}

func TestMemoryStoreIsTenantScoped(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.Save(ctx, "t1", samplePath()); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(ctx, "t2", samplePath()); err != nil {
		t.Fatal(err)
	}
	if len(m.ForTenant("t1")) != 1 || len(m.ForTenant("t2")) != 1 {
		t.Errorf("per-tenant counts = %d/%d, want 1/1", len(m.ForTenant("t1")), len(m.ForTenant("t2")))
	}
	if len(m.ForTenant("other")) != 0 {
		t.Error("an unrelated tenant should have no paths")
	}
}

func TestNewModes(t *testing.T) {
	if _, err := New("memory", ""); err != nil {
		t.Errorf("memory: %v", err)
	}
	if _, err := New("", ""); err != nil {
		t.Errorf("default: %v", err)
	}
	if _, err := New("clickhouse", ""); err == nil {
		t.Error("clickhouse without a URL should error")
	}
	if _, err := New("bogus", ""); err == nil {
		t.Error("unknown mode should error")
	}
}
