// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

func samplePath() *path.Path {
	return &path.Path{
		Target: "8.8.8.8", TargetIP: "8.8.8.8", Mode: "icmp", MaxHops: 30, TraceCount: 2, DestinationReached: true,
		MeasurementFidelity: &path.MeasurementFidelity{
			Version: 1, ProbeTransport: "icmp", AcquisitionMode: "raw_icmp",
			TimingSource: "application_monotonic", HopVisibility: "full",
		},
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
	if len(m.forTenant("t1")) != 1 || len(m.forTenant("t2")) != 1 {
		t.Errorf("per-tenant counts = %d/%d, want 1/1", len(m.forTenant("t1")), len(m.forTenant("t2")))
	}
	if len(m.forTenant("other")) != 0 {
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
	if p.MeasurementFidelity == nil || p.MeasurementFidelity.AcquisitionMode != "raw_icmp" {
		t.Errorf("latest measurement fidelity = %+v", p.MeasurementFidelity)
	}
	if _, ok, _ := m.Latest(ctx, "t1", "1.1.1.1"); ok {
		t.Error("unknown target should not be found")
	}
	if _, ok, _ := m.Latest(ctx, "other-tenant", "8.8.8.8"); ok {
		t.Error("another tenant must not see this tenant's path")
	}
}

func TestMemoryPathHistoryTenantTargetAndCopiedIDIsolation(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	before := time.Now().UTC().Add(-time.Second)

	pathA := samplePath()
	pathA.TargetIP = "198.51.100.10"
	pathB := samplePath()
	pathB.TargetIP = "192.0.2.99"
	otherTarget := samplePath()
	otherTarget.Target = "one.one.one.one"
	if err := m.Save(ctx, "tenant-a", pathA); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(ctx, "tenant-b", pathB); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(ctx, "tenant-a", otherTarget); err != nil {
		t.Fatal(err)
	}

	roundsA, err := m.History(ctx, "tenant-a", "8.8.8.8", HistoryQuery{
		From: before, To: time.Now().UTC().Add(time.Second), Limit: 10,
	})
	if err != nil || len(roundsA) != 1 {
		t.Fatalf("tenant A history: len=%d err=%v", len(roundsA), err)
	}
	if roundsA[0].Path.TargetIP != "198.51.100.10" {
		t.Fatalf("tenant A read wrong path: %+v", roundsA[0].Path)
	}
	roundsB, err := m.History(ctx, "tenant-b", "8.8.8.8", HistoryQuery{})
	if err != nil || len(roundsB) != 1 {
		t.Fatalf("tenant B history: len=%d err=%v", len(roundsB), err)
	}

	// A stable URL's opaque round ID is only a selector. Replaying B's ID in
	// A's session, or A's ID against another target, returns nothing.
	if got, err := m.History(ctx, "tenant-a", "8.8.8.8", HistoryQuery{IDs: []string{roundsB[0].ID}}); err != nil || len(got) != 0 {
		t.Fatalf("copied cross-tenant round ID: len=%d err=%v", len(got), err)
	}
	if got, err := m.History(ctx, "tenant-a", "one.one.one.one", HistoryQuery{IDs: []string{roundsA[0].ID}}); err != nil || len(got) != 0 {
		t.Fatalf("copied cross-target round ID: len=%d err=%v", len(got), err)
	}
	if _, err := m.History(ctx, "", "8.8.8.8", HistoryQuery{}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("unscoped history = %v, want ErrNoTenant", err)
	}

	// Returned rounds are deep copies. A caller cannot mutate stored evidence.
	roundsA[0].Path.Hops[0].Nodes[0].IP = "mutated"
	roundsA[0].Path.MeasurementFidelity.AcquisitionMode = "mutated"
	again, err := m.History(ctx, "tenant-a", "8.8.8.8", HistoryQuery{})
	if err != nil || again[0].Path.Hops[0].Nodes[0].IP == "mutated" {
		t.Fatalf("history snapshot was not cloned: %+v err=%v", again, err)
	}
	if again[0].Path.MeasurementFidelity == nil || again[0].Path.MeasurementFidelity.AcquisitionMode != "raw_icmp" {
		t.Fatalf("history fidelity was not cloned: %+v", again[0].Path.MeasurementFidelity)
	}
}

func TestNewModes(t *testing.T) {
	if _, err := xNew("memory", ""); err != nil {
		t.Errorf("memory: %v", err)
	}
	if _, err := xNew("", ""); err != nil {
		t.Errorf("default: %v", err)
	}
	if _, err := xNew("clickhouse", ""); err == nil {
		t.Error("clickhouse without a URL should error")
	}
	if _, err := xNew("bogus", ""); err == nil {
		t.Error("unknown mode should error")
	}
}

func TestLegacyClickHouseRowLeavesMeasurementFidelityUnknown(t *testing.T) {
	if got := fidelityFromRow(map[string]any{
		"mode":             "icmp",
		"fidelity_version": 0,
	}); got != nil {
		t.Fatalf("legacy row was backfilled from mode: %+v", got)
	}
}
