// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

func TestFullStackFlowReportRendering(t *testing.T) {
	rep := FullStackFlowReport{
		Profile:        Profile{Tier: TierS},
		AtCIScale:      true,
		Namespace:      "lfunit",
		Records:        10,
		Stored:         9,
		TenantsQueried: 2,
		RecordsSec:     1234,
		InsertLatency:  LatencyStat{P95: 3 * time.Millisecond},
		QueryP95:       4 * time.Millisecond,
		Published:      2,
		Produced:       2,
		PartsBefore:    flowstore.PartPressure{ActiveParts: 5},
		PartsAfter:     flowstore.PartPressure{ActiveParts: 8, Rows: 9},
		MaxNewParts:    10,
		Violations:     []string{"missing one row"},
	}
	if got := rep.String(); !strings.Contains(got, "full-stack-flow S") || !strings.Contains(got, "FAIL") {
		t.Fatalf("report row = %s", got)
	}
	if got := rep.Diagnostics(); !strings.Contains(got, "stored=9/10") || !strings.Contains(got, "active_parts before=5 after=8") {
		t.Fatalf("diagnostics = %s", got)
	}
	rep.Violations = nil
	if got := rep.String(); !strings.Contains(got, "PASS") {
		t.Fatalf("healthy report row = %s", got)
	}
}

func TestFlowTenantLoadAndRecordHelpers(t *testing.T) {
	load := buildFlowTenantLoad("lfunit", 3, 10)
	if got := []int{load[0].Expected, load[1].Expected, load[2].Expected}; got[0] != 4 || got[1] != 3 || got[2] != 3 {
		t.Fatalf("tenant split = %v, want 4/3/3", got)
	}
	if load[0].ID != "lfunit-tenant-0000" || load[2].Source != "10.0.2.1" || load[2].Exporter != "192.0.2.3" {
		t.Fatalf("tenant identity helpers = %+v", load)
	}

	base := time.Unix(1_700_000_000, 0).UTC()
	rec := buildFlowRecord(load[1], 1, base, 42)
	if rec.TenantId != load[1].ID || rec.AgentId != load[1].Agent || rec.SourceAddress != load[1].Source {
		t.Fatalf("record identity = %+v", rec)
	}
	if rec.ObservedAtUnixNano <= rec.EndUnixNano || rec.StartUnixNano >= rec.EndUnixNano {
		t.Fatalf("record timestamps not ordered: start=%d end=%d observed=%d", rec.StartUnixNano, rec.EndUnixNano, rec.ObservedAtUnixNano)
	}
	if rec.BytesScaled != rec.Bytes || rec.PacketsScaled != rec.Packets || rec.DestinationPort != 443 {
		t.Fatalf("record counters/ports = %+v", rec)
	}

	if batchesFor(0, 100) != 0 || batchesFor(11, 5) != 3 || batchesFor(2, 0) != 2 {
		t.Fatalf("batchesFor returned unexpected values")
	}
	if maxDuration(time.Second, 2*time.Second) != 2*time.Second {
		t.Fatal("maxDuration did not return the larger duration")
	}
	if !flowBaseTime(10).Before(time.Now()) {
		t.Fatal("flowBaseTime must be safely in the past")
	}
}

func TestPublishFlowTenantBatches(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()
	load := buildFlowTenantLoad("lfpub", 2, 5)
	var lat Latencies
	published, batches, err := publishFlowTenantBatches(context.Background(), b, "flow-topic", load, time.Now().UTC(), 2, &lat)
	if err != nil {
		t.Fatalf("publishFlowTenantBatches: %v", err)
	}
	if published != 3 || batches != 3 {
		t.Fatalf("published=%d batches=%d, want 3/3", published, batches)
	}
	if lat.Summary().Count != 3 {
		t.Fatalf("latency samples = %+v, want 3", lat.Summary())
	}
}

func TestTimedFlowStoreAndConfirmFlowTenants(t *testing.T) {
	ctx := context.Background()
	mem := flowstore.NewMemory()
	var lat Latencies
	timed := &timedFlowStore{Store: mem, lat: &lat}
	tenants := buildFlowTenantLoad("lfconfirm", 2, 5)
	base := time.Now().UTC().Add(-time.Minute)
	var rows []flowstore.Row
	for _, tenant := range tenants {
		for i := 0; i < tenant.Expected; i++ {
			rows = append(rows, flowstore.Row{
				TenantID:      tenant.ID,
				AgentID:       tenant.Agent,
				Exporter:      tenant.Exporter,
				TS:            base.Add(time.Duration(i) * time.Second),
				StartTS:       base.Add(-time.Minute),
				SrcAddr:       tenant.Source,
				DstAddr:       "203.0.113.1",
				Bytes:         100,
				Packets:       2,
				Sampling:      1,
				BytesScaled:   100,
				PacketsScaled: 2,
			})
		}
	}
	rows = append(rows, flowstore.Row{TenantID: "foreign", TS: base, SrcAddr: tenants[0].Source, BytesScaled: 9_999, PacketsScaled: 99})
	if err := timed.Insert(ctx, rows); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if lat.Summary().Count != 1 {
		t.Fatalf("insert latency samples = %+v, want 1", lat.Summary())
	}

	var queryLat Latencies
	total, mismatches, err := confirmFlowTenants(ctx, mem, tenants, time.Now().UTC(), 10*time.Minute, &queryLat)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if total != 5 || len(mismatches) != 0 || queryLat.Summary().Count != 2 {
		t.Fatalf("confirm total=%d mismatches=%v queryLat=%+v", total, mismatches, queryLat.Summary())
	}

	tenants[0].Expected++
	_, mismatches, err = confirmFlowTenants(ctx, mem, tenants, time.Now().UTC(), 10*time.Minute, &queryLat)
	if err != nil {
		t.Fatalf("confirm mismatch: %v", err)
	}
	if len(mismatches) == 0 || !strings.Contains(mismatches[0], "want exactly") {
		t.Fatalf("missing completeness mismatch: %v", mismatches)
	}
}
