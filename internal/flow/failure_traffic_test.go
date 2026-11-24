// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFailureTrafficUsesConcurrentDirectionalLoad(t *testing.T) {
	scope := tenancy.WithTenant(t.Context(), tenancy.ID("owner-tenant"))
	first := FailurePort{InterfaceID: "primary", Direction: "out"}
	backup := FailurePort{InterfaceID: "backup", Direction: "out"}
	reverse := FailurePort{InterfaceID: "backup", Direction: "in"}
	shared := FailurePort{InterfaceID: "access", Direction: "in"}
	beyond := FailurePort{InterfaceID: "downstream", Direction: "out"}
	begin := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	sample := FailureTrafficSample{
		TenantID: "owner-tenant", From: begin, To: begin.Add(5 * time.Minute), DemandComplete: true,
		Failed: []FailurePort{first},
		Baselines: []FailureTrafficBaseline{
			{FailurePort: first, BPS: big.NewRat(500, 1), CapacityBPS: 1000},
			{FailurePort: backup, BPS: big.NewRat(650, 1), CapacityBPS: 1000},
			{FailurePort: reverse, BPS: big.NewRat(20, 1), CapacityBPS: 1000},
			{FailurePort: shared, BPS: big.NewRat(700, 1), CapacityBPS: 1000},
			{FailurePort: beyond, BPS: big.NewRat(130, 1), CapacityBPS: 1000},
		},
		Demands: []FailureTrafficDemand{
			{BPS: big.NewRat(400, 1), Before: []FailurePort{shared, first}, After: []FailurePort{shared, backup}, Disposition: FailureTrafficRerouted},
			{BPS: big.NewRat(100, 1), Before: []FailurePort{shared, first, beyond}, After: []FailurePort{shared}, Disposition: FailureTrafficUnrouted},
		},
	}
	const budget = 8 << 20
	result, err := ProjectFailureTrafficSample(scope, sample, budget, budget)
	if err != nil || !result.Complete || len(result.Ports) != 5 || result.AffectedBPS != "500" ||
		result.ReroutedBPS != "400" || result.UnroutedBPS != "100" || result.UnresolvedBPS != "0" {
		t.Fatalf("unexpected traffic balance: %+v (%v)", result, err)
	}
	rows := make(map[FailurePort]FailureTrafficPortProjection)
	for _, row := range result.Ports {
		rows[row.FailurePort] = row
	}
	if row := rows[backup]; row.MeasuredBPS != "650" || row.AddedBPS != "400" || row.ProjectedBPS != "1050" || row.UtilizationRatio != "21/20" {
		t.Fatalf("overloaded backup lost its exact offered load: %+v", row)
	}
	if rows[reverse].ProjectedBPS != "20" || rows[shared].ProjectedBPS != "700" || rows[beyond].ProjectedBPS != "30" ||
		rows[first].Status != "failed" || rows[first].MeasuredBPS != "500" || rows[first].ProjectedBPS != "" {
		t.Fatalf("shared, reverse, and failed links were miscounted: %+v", rows)
	}
	incomplete := sample
	incomplete.Baselines = slices.Clone(sample.Baselines)
	incomplete.Baselines[0].BPS = big.NewRat(600, 1)
	if got, err := ProjectFailureTrafficSample(scope, incomplete, budget, budget); err != nil || got.Complete || got.ReroutedBPS != "400" ||
		!slices.ContainsFunc(got.Ports, func(row FailureTrafficPortProjection) bool {
			return row.FailurePort == backup && row.Status == "traffic_unresolved" && row.ProjectedBPS == ""
		}) {
		t.Fatalf("a small flow population was represented as complete egress demand: %+v (%v)", got, err)
	}
	destination := netip.MustParseAddr("203.0.113.12")
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	before := []FailurePort{shared, first}
	after := []FailurePort{shared, backup}
	failed := map[FailurePort]bool{first: true}
	evidence := FailureRouteEvidence{Selected: []FailureRouteCandidate{{Prefix: prefix, Ports: before}}, EligibleComplete: true}
	defaultRoute := FailureRouteCandidate{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Ports: []FailurePort{shared, beyond}}
	survivor := FailureRouteCandidate{Prefix: prefix, Ports: after}
	unmapped := FailureRouteCandidate{Prefix: netip.MustParsePrefix("203.0.113.0/25")}
	for _, test := range []struct {
		name     string
		eligible []FailureRouteCandidate
		want     FailureTrafficDisposition
		path     []FailurePort
	}{
		{name: "longest surviving route", eligible: []FailureRouteCandidate{defaultRoute, survivor}, want: FailureTrafficRerouted, path: after},
		{name: "unmapped more-specific route", eligible: []FailureRouteCandidate{defaultRoute, survivor, unmapped}, want: FailureTrafficUnresolved},
		{name: "complete view has no surviving route", want: FailureTrafficUnrouted, path: []FailurePort{shared}},
	} {
		evidence.Eligible = test.eligible
		disposition, route, err := ChooseFailureTrafficRoute(scope, destination, before, failed, evidence)
		if err != nil || disposition != test.want || !slices.Equal(route, test.path) {
			t.Fatalf("%s: disposition=%q route=%v error=%v", test.name, disposition, route, err)
		}
	}

	later := sample
	later.From, later.To = sample.To, sample.To.Add(5*time.Minute)
	later.Baselines = slices.Clone(sample.Baselines)
	later.Baselines[0].BPS, later.Baselines[1].BPS = big.NewRat(250, 1), big.NewRat(800, 1)
	later.Demands = slices.Clone(sample.Demands)
	later.Demands[0].BPS = big.NewRat(150, 1)
	series, err := ProjectFailureTrafficSeries(scope, []FailureTrafficSample{sample, later}, later.To.Add(time.Hour), budget, budget)
	if err != nil || !series.Complete || series.AffectedBytes != "28125" {
		t.Fatalf("unexpected series volume: %+v (%v)", series, err)
	}
	out := slices.IndexFunc(series.Ports, func(row FailureTrafficPortSeries) bool {
		return row.FailurePort == backup
	})
	if out < 0 {
		t.Fatal("missing backup from the series")
	}
	backupSeries := series.Ports[out]
	if backupSeries.ProjectedPeak == nil || backupSeries.ProjectedPeak.BPS != "1050" || !backupSeries.ProjectedPeak.From.Equal(begin) ||
		backupSeries.MeasuredPeak == nil || backupSeries.MeasuredPeak.BPS != "800" || !backupSeries.MeasuredPeak.From.Equal(later.From) ||
		backupSeries.AtCapacity == nil || *backupSeries.AtCapacity || backupSeries.RunoutStatus != "weekly_repetitions_missing" {
		t.Fatalf("disjoint traffic peaks were combined or training coverage invented: %+v", backupSeries)
	}

	sample.Demands[0].Disposition = FailureTrafficUnresolved
	sample.Demands[0].After = nil
	result, err = ProjectFailureTrafficSample(scope, sample, budget, budget)
	if err != nil || result.Complete || result.UnresolvedBPS != "400" {
		t.Fatalf("incomplete alternate route was represented as a known load: %+v (%v)", result, err)
	}
	for _, row := range result.Ports {
		if row.ProjectedBPS != "" {
			t.Fatalf("incomplete routes yielded projected load: %+v", row)
		}
	}
	sibling := tenancy.WithTenant(t.Context(), tenancy.ID("sibling-tenant"))
	if _, err := ProjectFailureTrafficSample(sibling, sample, budget, budget); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatalf("projection accepted sibling traffic: %v", err)
	}
}

// ProjectFailureTrafficSample computes offered load. It retains exact rates
// above physical capacity so an overloaded survivor remains visible. Receipts,
// routing precedence and actor permissions belong to the upstream readers.
func ProjectFailureTrafficSample(ctx context.Context, sample FailureTrafficSample, memoryBytes, workUnits int64) (FailureTrafficProjection, error) {
	budget := capacityGridAdmission{memory: memoryBytes, work: workUnits}
	return projectFailureTrafficSample(ctx, sample, &budget)
}
