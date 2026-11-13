// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package pathstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// U-026: the cross-tenant isolation gate against REAL ClickHouse for the
// path store. Runs in CI (containerized CH via PROBECTL_PATHSTORE_URL);
// skips locally when unset.
func TestClickHousePathCrossTenantIsolation(t *testing.T) {
	url := os.Getenv("PROBECTL_PATHSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_PATHSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := newClickHouse(url)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ta := fmt.Sprintf("path-iso-a-%d", now.UnixNano())
	tb := fmt.Sprintf("path-iso-b-%d", now.UnixNano())
	target := fmt.Sprintf("shared-target-%d.example", now.UnixNano())

	mk := func(ip string, traces int) *path.Path {
		return &path.Path{
			Target: target, TargetIP: ip, Mode: "icmp", MaxHops: 8, TraceCount: traces, DestinationReached: true,
			MeasurementFidelity: &path.MeasurementFidelity{
				Version: 1, ProbeTransport: "icmp", AcquisitionMode: "raw_icmp",
				TimingSource: "application_monotonic", HopVisibility: "full",
			},
			Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: ip, Sent: 1, Received: 1, RTTAvgMs: 1.5}}}},
		}
	}
	if err := c.Save(ctx, ta, mk("198.51.100.10", 2)); err != nil {
		t.Fatalf("save A: %v", err)
	}
	if err := c.Save(ctx, tb, mk("192.0.2.99", 7)); err != nil {
		t.Fatalf("save B: %v", err)
	}

	// Tenant A's latest path for the SHARED target name must be A's, never B's.
	got, ok, err := c.Latest(ctx, ta, target)
	if err != nil || !ok {
		t.Fatalf("latest A: ok=%v err=%v", ok, err)
	}
	if got.TargetIP != "198.51.100.10" {
		t.Fatalf("CROSS-TENANT LEAK: tenant A read %q", got.TargetIP)
	}
	if got.MeasurementFidelity == nil || got.MeasurementFidelity.AcquisitionMode != "raw_icmp" {
		t.Fatalf("tenant A fidelity missing or crossed: %+v", got.MeasurementFidelity)
	}
	roundsA, err := c.History(ctx, ta, target, HistoryQuery{})
	if err != nil || len(roundsA) != 1 || roundsA[0].Path.TargetIP != "198.51.100.10" {
		t.Fatalf("history A: rounds=%+v err=%v", roundsA, err)
	}
	roundsB, err := c.History(ctx, tb, target, HistoryQuery{})
	if err != nil || len(roundsB) != 1 || roundsB[0].Path.TargetIP != "192.0.2.99" {
		t.Fatalf("history B: rounds=%+v err=%v", roundsB, err)
	}
	if got.TraceCount != 2 || got.MaxHops != 8 || roundsA[0].Path.TraceCount != 2 || roundsB[0].Path.TraceCount != 7 {
		t.Fatalf("cross-tenant discovery metadata: latest A=%+v history A=%+v B=%+v", got, roundsA, roundsB)
	}
	// Incident source joins consume the whole admitted history, not the
	// browser's default page. Write both populations through the real store.
	var population []PathItem
	for i := range 256 {
		for _, tenant := range []string{ta, tb} {
			ip, traces := "198.51.100.10", 2
			if tenant == tb {
				ip, traces = "192.0.2.99", 7
			}
			started := now.Add(-time.Minute).Add(time.Duration(i) * time.Millisecond)
			population = append(population, PathItem{TenantID: tenant, P: mk(ip, traces), ObservedAt: started, CompletedAt: started.Add(123 * time.Nanosecond), TrustedDiscoveryTime: true})
		}
	}
	if err := c.SaveBatch(ctx, population); err != nil {
		t.Fatal("complete two-tenant path population", err)
	}
	for _, tenant := range []string{ta, tb} {
		rounds, err := c.History(ctx, tenant, target, HistoryQuery{Limit: 1, MaxBytes: 16 << 20})
		if err != nil || len(rounds) != 257 {
			t.Fatal("complete history inherited a page or lost rounds", len(rounds), err)
		}
		want := "198.51.100.10"
		if tenant == tb {
			want = "192.0.2.99"
		}
		completed := 0
		for _, round := range rounds {
			if round.Path.TargetIP != want {
				t.Fatal("complete ClickHouse history crossed tenant storage scope")
			}
			if round.CompletedAt != nil {
				completed++
				if round.CompletedAt.Sub(round.ObservedAt) != 123*time.Nanosecond {
					t.Fatal("retained path execution clock lost nanoseconds")
				}
			}
		}
		if completed != 256 {
			t.Fatal("completion clocks were omitted or fabricated for legacy rounds", completed)
		}
		point := rounds[0]
		narrow, err := c.History(ctx, tenant, target, HistoryQuery{From: point.ObservedAt, To: point.ObservedAt.Add(time.Nanosecond), MaxBytes: 16 << 20})
		if err != nil || len(narrow) != 1 || narrow[0].ID != point.ID {
			t.Fatal("exact complete selector lost its included millisecond point", len(narrow), err)
		}
		empty, err := c.History(ctx, tenant, target, HistoryQuery{From: point.ObservedAt.Add(time.Nanosecond), To: point.ObservedAt.Add(2 * time.Nanosecond), MaxBytes: 16 << 20})
		if err != nil || len(empty) != 0 {
			t.Fatal("complete selector rounded an excluded point into the window", len(empty), err)
		}
	}
	// Replaying B's stable round ID in A's authenticated scope must be a
	// clean miss. path_id is never authorization by itself.
	foreign, err := c.History(ctx, ta, target, HistoryQuery{IDs: []string{roundsB[0].ID}, MaxBytes: 16 << 20})
	if err != nil || len(foreign) != 0 {
		t.Fatalf("CROSS-TENANT HISTORY LEAK: rounds=%+v err=%v", foreign, err)
	}

	// The empty-tenant refusal (defense in depth) holds on the live store too.
	if _, _, err := c.Latest(ctx, "", target); err == nil {
		t.Fatal("unscoped Latest must refuse (ErrNoTenant)")
	}
	if _, err := c.History(ctx, "", target, HistoryQuery{}); err == nil {
		t.Fatal("unscoped History must refuse (ErrNoTenant)")
	}
}
