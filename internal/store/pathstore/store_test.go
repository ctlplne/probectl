package pathstore

import (
	"context"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/path"
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

func TestMemoryLatest(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	old := samplePath()
	old.TargetIP = "8.8.8.8-old"
	newer := samplePath()
	newer.TargetIP = "8.8.8.8-new"
	_ = m.Save(ctx, "t1", old)
	_ = m.Save(ctx, "t1", newer)

	p, ok, err := m.Latest(ctx, "t1", "8.8.8.8")
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v", ok, err)
	}
	if p.TargetIP != "8.8.8.8-new" {
		t.Errorf("latest should be the newest save, got %q", p.TargetIP)
	}
	if _, ok, _ := m.Latest(ctx, "t1", "1.1.1.1"); ok {
		t.Error("unknown target should not be found")
	}
	if _, ok, _ := m.Latest(ctx, "other-tenant", "8.8.8.8"); ok {
		t.Error("another tenant must not see this tenant's path")
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
