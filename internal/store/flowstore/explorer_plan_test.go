// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestExplorerPlanSnapshotClockUsesContributingInput(t *testing.T) {
	memory := NewMemory()
	matched := explorerFixtureRow("red")
	unmatched := matched
	unmatched.TS = matched.TS.Add(-24 * time.Hour)
	unmatched.DstPort = 80
	foreign := matched
	foreign.TenantID = "blue"
	foreign.TS = matched.TS.Add(-48 * time.Hour)
	if err := memory.Insert(t.Context(), []Row{matched, unmatched, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: matched.TS.AddDate(-2, 0, 0), To: matched.TS.Add(time.Hour), BucketSeconds: 3600, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil || !result.OldestInput.Equal(matched.TS) {
		t.Fatalf("wrong contributing-input clock: %s %v", result.OldestInput, err)
	}
	plan.Filter.Conditions[0].Values = []string{"999"}
	result, err = memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil || !result.OldestInput.IsZero() {
		t.Fatalf("empty query invented an input clock: %s %v", result.OldestInput, err)
	}
}

func TestExplorerPlanGoldenSparseStatisticsAndTenantBoundary(t *testing.T) {
	first := explorerFixtureRow("red")
	first.BytesScaled = 100
	second := first
	second.TS = first.TS.Add(time.Minute)
	second.BytesScaled = 200
	second.SrcPort++
	foreign := first
	foreign.TenantID = "blue"
	foreign.BytesScaled = ^uint64(0)
	store := NewMemory()
	if err := store.Insert(t.Context(), []Row{first, second, foreign, first}); err != nil {
		t.Fatal(err)
	}
	metrics := []flow.QueryMetric{}
	for _, measure := range []string{"bytes", "bps", "unique_src", "unique_src_port", "unique_src_asn", "unique_src_country", "fps"} {
		calculations := []string{"avg", "p95", "p99", "max", "total"}
		if strings.HasPrefix(measure, "unique_") {
			calculations = append(calculations, "bucket_total")
		}
		for _, calc := range calculations {
			role := "additional"
			if len(metrics) == 0 {
				role = "primary"
			}
			metrics = append(metrics, flow.QueryMetric{Measure: measure, Calculation: calc, Role: role})
		}
	}
	plan := flow.QueryPlan{From: first.TS, To: first.TS.Add(20 * time.Minute), BucketSeconds: 60, Metrics: metrics}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.TotalGroups != 1 {
		t.Fatalf("result shape %+v", result)
	}
	for key, want := range map[string]string{"bytes:avg": "15", "bytes:p95": "100", "bytes:p99": "200", "bytes:max": "200", "bytes:total": "300", "bps:avg": "2", "bps:total": "300", "unique_src:total": "1", "unique_src:bucket_total": "2", "unique_src:p95": "1", "unique_src_port:total": "2", "unique_src_port:p99": "1", "unique_src_asn:total": "1", "unique_src_country:total": "1", "fps:total": "2"} {
		if got := result.Rows[0].Metrics[key]; got != want {
			t.Errorf("%s=%s want %s", key, got, want)
		}
	}
	if _, err := store.ExplorePlan(t.Context(), PlanQuery{Plan: plan}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("scope absent: %v", err)
	}
	result, err = store.ExplorePlan(t.Context(), PlanQuery{TenantID: "absent", Plan: plan})
	if err != nil || len(result.Rows) != 0 || result.Totals["bytes:total"] != "0" {
		t.Fatalf("empty tenant: %+v %v", result, err)
	}
}

func TestExplorerPlanNestedOperatorsEightDimensionsAndExactOther(t *testing.T) {
	first := explorerFixtureRow("red")
	first.BytesScaled = ^uint64(0)
	second := first
	second.SrcPort++
	second.BytesScaled = ^uint64(0)
	tail := first
	tail.Transport = "udp"
	tail.BytesScaled = 10
	tail.SrcPort = 53
	tail2 := tail
	tail2.SrcPort = 54
	tail2.BytesScaled = 20
	foreign := first
	foreign.TenantID = "blue"
	store := NewMemory()
	if err := store.Insert(t.Context(), []Row{first, second, tail, tail2, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: first.TS, To: first.TS.Add(time.Hour), GroupBy: []string{"transport", "protocol", "exporter", "in_if", "out_if", "vlan", "dscp", "dst_country"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}, RowLimit: 1, PageSize: 1, View: "line", SeriesDepth: 1, Filter: &flow.QueryFilterGroup{Match: "all", Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryCIDR, Values: []string{"198.51.100.0/24"}}, {Field: "tcp_flags", Op: flow.QueryBitAnd, Values: []string{"2"}}}, Groups: []flow.QueryFilterGroup{{Match: "any", Conditions: []flow.QueryPredicate{{Field: "src_as_name", Op: flow.QueryRegex, Values: []string{"^Test source$"}}, {Field: "dst_port", Op: flow.QueryLess, Values: []string{"1"}}}}}}}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0].Metrics["bytes:total"] != "36893488147419103230" || result.Other == nil || result.Other.Metrics["bytes:total"] != "30" || result.Other.Metrics["unique_src:total"] != "1" || !result.DetailLimited {
		t.Fatalf("exact grouping/Other: %+v", result)
	}
	if len(result.Series) != 1 || len(result.OtherSeries) != 1 || !result.OtherSeries[0].Other || result.OtherSeries[0].Metrics["unique_src:total"] != "1" {
		t.Fatalf("chart membership and exact Other: %+v", result.Series)
	}
	if result.Totals["unique_src:total"] != "1" {
		t.Fatal("distinct total was a sum of group counts")
	}
}

func TestExplorerPlanTotalSeriesUsesTenantInputsNotGroupCardinalities(t *testing.T) {
	first := explorerFixtureRow("red")
	first.BytesScaled = ^uint64(0)
	second := first
	second.SrcPort++
	second.TS = first.TS.Add(10 * time.Second)
	last := first
	last.SrcPort += 2
	last.TS = first.TS.Add(125 * time.Second)
	last.BytesScaled = 9
	foreign, filtered := first, first
	foreign.TenantID = "blue"
	filtered.DstPort = 80
	memory := NewMemory()
	if err := memory.Insert(t.Context(), []Row{first, second, last, foreign, filtered, first}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: first.TS, To: first.TS.Add(150 * time.Second), View: "line", GroupBy: []string{"src_port"}, RowLimit: 1, PageSize: 1, SeriesDepth: 1, BucketSeconds: 60, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}, {Measure: "bps", Calculation: "avg", Role: "secondary"}, {Measure: "bytes", Calculation: "p95", Role: "additional"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TotalSeries) != 2 {
		t.Fatalf("total buckets %+v", result.TotalSeries)
	}
	firstPoint, lastPoint := result.TotalSeries[0], result.TotalSeries[1]
	if firstPoint.Other || len(firstPoint.Group) != 0 || !firstPoint.TS.Equal(first.TS) || firstPoint.DurationSeconds != "60.000000000" || firstPoint.Metrics["bytes:total"] != "36893488147419103230" || firstPoint.Metrics["unique_src:total"] != "1" || len(firstPoint.Metrics) != 3 {
		t.Fatalf("total mixed tenant/filter/group/additional data: %+v", firstPoint)
	}
	if !lastPoint.TS.Equal(first.TS.Add(120*time.Second)) || lastPoint.DurationSeconds != "30.000000000" || lastPoint.Metrics["bps:avg"] != "2.400000000000000000" {
		t.Fatalf("partial/idle bucket semantics: %+v", lastPoint)
	}
	if result.Series[0].Metrics["unique_src:total"] != "1" || result.OtherSeries[0].Metrics["unique_src:total"] != "1" {
		t.Fatal("fixture did not overlap identities across chart+Other")
	}
	otherOnly, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan, SelectedChartGroups: [][]string{}})
	if err != nil || len(otherOnly.Series) != 0 || !reflect.DeepEqual(otherOnly.TotalSeries, result.TotalSeries) {
		t.Fatalf("total depends on chart selection: %+v %v", otherOnly.TotalSeries, err)
	}
	plan.View = "matrix"
	plan.MatrixWith = []string{"dst_addr"}
	matrix, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil || !reflect.DeepEqual(matrix.TotalSeries, result.TotalSeries) {
		t.Fatalf("matrix changed total: %+v %v", matrix.TotalSeries, err)
	}
	plan.View = "table"
	plan.MatrixWith = nil
	table, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil || table.TotalSeries == nil || len(table.TotalSeries) != 0 {
		t.Fatalf("table emitted point stream: %+v %v", table.TotalSeries, err)
	}
	plan.View = "line"
	empty, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "absent", Plan: plan})
	if err != nil || len(empty.TotalSeries) != 0 {
		t.Fatalf("empty tenant total points: %+v %v", empty.TotalSeries, err)
	}
}

func TestExplorerPlanMatrixEightByEightAndFifteenValues(t *testing.T) {
	base := explorerFixtureRow("red")
	rows := []Row{}
	for i := 0; i < 16; i++ {
		r := base
		r.SrcAddr = fmt.Sprintf("192.0.2.%d", i+1)
		r.DstAddr = fmt.Sprintf("198.51.100.%d", i+1)
		r.BytesScaled = uint64(100 - i)
		rows = append(rows, r)
	}
	foreign := rows[0]
	foreign.TenantID = "blue"
	rows = append(rows, foreign)
	store := NewMemory()
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Hour), View: "matrix", GroupBy: []string{"src_addr", "src_port", "protocol", "exporter", "in_if", "vlan", "dscp", "src_asn"}, MatrixWith: []string{"dst_addr", "dst_port", "transport", "next_hop", "out_if", "net_type", "tcp_flags", "dst_country"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, MatrixDepth: 15}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	normal, other := 0, 0
	for _, cell := range result.Matrix {
		if cell.RowOther || cell.ColumnOther {
			other++
			if cell.Metrics["bytes:total"] != "85" {
				t.Fatalf("matrix Other: %+v", cell)
			}
		} else {
			normal++
			if len(cell.Row) != 8 || len(cell.Column) != 8 {
				t.Fatalf("lost dimensions: %+v", cell)
			}
		}
	}
	if normal != 15 || other != 1 {
		t.Fatalf("matrix published reach: normal=%d other=%d", normal, other)
	}
}

func TestExplorerPlanFiftyThousandDetailsSeparateFromFortyChartSeries(t *testing.T) {
	base := explorerFixtureRow("red")
	rows := make([]Row, 50000)
	for i := range rows {
		r := base
		r.SrcPort = uint16(i)
		r.BytesScaled = uint64(i + 1)
		rows[i] = r
	}
	store := NewMemory()
	// This is a correctness oracle under race instrumentation and package
	// contention. Keep a finite test-only budget; production defaults and
	// dedicated deadline/refusal tests remain unchanged.
	budget := DefaultExplorerBudget()
	budget.ExecutionLimit = 30 * time.Second
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Minute), GroupBy: []string{"src_port"}, RowLimit: 50000, PageSize: 5000, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 50000 || result.TotalGroups != 50000 || result.DetailLimited || result.Other != nil || len(result.Series) != 0 {
		t.Fatalf("table reach: rows=%d total=%d limited=%v Other=%v series=%d", len(result.Rows), result.TotalGroups, result.DetailLimited, result.Other, len(result.Series))
	}
	// A separate chart query still has all selected detail rows, independent of
	// its top 40 identities and a separate structural Other summary series.
	plan.View = "line"
	plan.RowLimit = 350
	plan.PageSize = 350
	plan.SeriesDepth = 40
	result, err = store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 350 || len(result.Series) != 40 || len(result.OtherSeries) != 1 || !result.OtherSeries[0].Other {
		t.Fatalf("chart reach: details=%d series=%d", len(result.Rows), len(result.Series))
	}
}

func TestExplorerPlanLongRangeNested250AndCancellation(t *testing.T) {
	base := explorerFixtureRow("red")
	store := NewMemory()
	if err := store.Insert(t.Context(), []Row{base}); err != nil {
		t.Fatal(err)
	}
	conditions := make([]flow.QueryPredicate, 250)
	for i := range conditions {
		conditions[i] = flow.QueryPredicate{Field: "dst_port", Op: flow.QueryGreater, Values: []string{"0"}}
	}
	plan := flow.QueryPlan{From: base.TS.AddDate(-2, 0, 0), To: base.TS.Add(time.Minute), BucketSeconds: 604800, Filter: &flow.QueryFilterGroup{Conditions: conditions}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil || len(result.Rows) != 1 || result.Rows[0].Metrics["bytes:total"] != "12300" {
		t.Fatalf("long range/published filter reach: %+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.ExplorePlan(ctx, PlanQuery{TenantID: "red", Plan: plan}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	plan.Filter = &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: "unresolved"}}}
	if _, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan}); err == nil {
		t.Fatal("unresolved saved filter bypassed tenant resolver")
	}
	before := base
	plan.Filter = nil
	_, _ = store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if !reflect.DeepEqual(base, before) {
		t.Fatal("query mutated input")
	}
}

func TestExplorerPlanMatrixColumnsUseTheSelectedRowPopulation(t *testing.T) {
	base := explorerFixtureRow("red")
	a := base
	a.SrcAddr = "192.0.2.1"
	a.DstAddr = "198.51.100.1"
	a.BytesScaled = 90
	b := a
	b.DstAddr = "198.51.100.2"
	b.BytesScaled = 10
	c := base
	c.SrcAddr = "192.0.2.2"
	c.DstAddr = "198.51.100.3"
	c.BytesScaled = 99
	foreign := c
	foreign.TenantID = "blue"
	foreign.BytesScaled = 100000
	store := NewMemory()
	if err := store.Insert(t.Context(), []Row{a, b, c, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Minute), View: "matrix", GroupBy: []string{"src_addr"}, MatrixWith: []string{"dst_addr"}, MatrixDepth: 1, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cell := range result.Matrix {
		if !cell.RowOther && !cell.ColumnOther {
			found = true
			if cell.Row["src_addr"] != a.SrcAddr || cell.Column["dst_addr"] != a.DstAddr || cell.Metrics["bytes:total"] != "90" {
				t.Fatalf("matrix used global rather than row-conditioned columns: %+v", cell)
			}
		}
	}
	if !found {
		t.Fatal("globally popular column displaced every relevant column")
	}
}

func TestExplorerPlanComparisonMembershipKeepsTheSameOtherPopulation(t *testing.T) {
	base := explorerFixtureRow("red")
	rows := []Row{}
	for i, name := range []string{"A", "B", "Other"} {
		row := base
		row.Protocol = name
		row.BytesScaled = uint64(100 - i)
		rows = append(rows, row)
	}
	foreign := base
	foreign.TenantID = "blue"
	foreign.Protocol = "SECRET"
	rows = append(rows, foreign)
	store := NewMemory()
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Minute), GroupBy: []string{"protocol"}, View: "line", RowLimit: 2, PageSize: 2, SeriesDepth: 1, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}}
	for _, selected := range [][][]string{{{"B"}, {"A"}}, {{"Other"}}, {{"missing"}}, {}} {
		result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan, SelectedGroups: selected, SelectedChartGroups: selected[:min(len(selected), plan.SeriesDepth)]})
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case len(selected) == 2:
			if len(result.Rows) != 2 || result.Rows[0].Group["protocol"] != "B" || result.Other == nil || result.Other.Metrics["bytes:total"] != "98" || len(result.Series) != 1 || result.Series[0].Group["protocol"] != "B" || len(result.OtherSeries) != 1 || result.OtherSeries[0].Metrics["bytes:total"] != "198" {
				t.Fatalf("membership/rank or Other population drifted: %+v", result)
			}
		case len(selected) == 1 && selected[0][0] == "Other":
			if len(result.Rows) != 1 || result.Rows[0].Other || result.Rows[0].Group["protocol"] != "Other" || result.Other.Metrics["bytes:total"] != "199" {
				t.Fatalf("real Other collided with structural Other: %+v", result)
			}
		default:
			if len(result.Rows) != 0 || result.Other == nil || result.Other.Metrics["bytes:total"] != "297" || result.TotalGroups != 3 || len(result.Series) != 0 || len(result.OtherSeries) != 1 {
				t.Fatalf("empty/absent pinned selection hid own population: %+v", result)
			}
		}
		if result.Totals["unique_src:total"] != "1" {
			t.Fatal("comparison crossed tenant or summed distinct counts")
		}
	}
	if _, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan, SelectedGroups: [][]string{{"A"}, {"A"}}}); err == nil {
		t.Fatal("ambiguous duplicate membership accepted")
	}
}

func TestExplorerPlanPinnedMatrixAxesPreserveOtherAndConditionedStats(t *testing.T) {
	memory := NewMemory()
	base := explorerFixtureRow("red")
	a := base
	a.SrcAddr = "192.0.2.1"
	a.DstAddr = "198.51.100.1"
	a.BytesScaled = 100
	b := a
	b.SrcAddr = "192.0.2.2"
	b.DstAddr = "198.51.100.2"
	b.BytesScaled = 90
	foreign := a
	foreign.TenantID = "blue"
	foreign.BytesScaled = 99999
	if err := memory.Insert(t.Context(), []Row{a, b, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Minute), View: "matrix", GroupBy: []string{"src_addr"}, MatrixWith: []string{"dst_addr"}, MatrixDepth: 1, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan, SelectedGroups: [][]string{{b.SrcAddr}, {a.SrcAddr}}, SelectedMatrixRows: [][]string{{b.SrcAddr}}, SelectedColumns: [][]string{{a.DstAddr}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatrixColumns) != 0 {
		t.Fatal("fabricated conditioned statistics for a column present only in Other rows")
	}
	found := false
	for _, cell := range result.Matrix {
		if cell.RowOther && !cell.ColumnOther && cell.Column["dst_addr"] == a.DstAddr && cell.Metrics["bytes:total"] == "100" {
			found = true
		}
		if !cell.RowOther && (cell.Row["src_addr"] != b.SrcAddr || !cell.ColumnOther || cell.Metrics["bytes:total"] != "90") {
			t.Fatalf("matrix ignored pinned row/column axes: %+v", cell)
		}
	}
	if !found || result.Totals["bytes:total"] != "190" || result.Totals["unique_src:total"] != "2" {
		t.Fatal("matrix changed population or tenant scope")
	}
}

func TestMemoryNativePlanPublishesCompleteCoverage(t *testing.T) {
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	store := NewMemory()
	if err := store.Insert(t.Context(), []Row{{TenantID: "red", TS: at, Protocol: "red-only", BytesScaled: 9007199254740993}, {TenantID: "blue", TS: at, Protocol: "blue-only", BytesScaled: 9007199254740994}}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"red", "blue"} {
		result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}})
		if err != nil {
			t.Fatal(err)
		}
		if result.Source != "raw" || result.ResolutionSeconds != flow.MinPlanBucketSeconds || result.Coverage == nil || !result.Coverage.CompleteInputs || result.Coverage.ResolutionSeconds != flow.MinPlanBucketSeconds {
			t.Fatalf("reference backend omitted actual native source coverage: %+v", result.Coverage)
		}
		if len(result.Coverage.Fields) != len(flow.QueryFields()) || len(result.Rows) != 1 || result.Rows[0].Group["protocol"] != tenant+"-only" {
			t.Fatal("reference coverage narrowed registry or crossed tenant")
		}
	}
}
