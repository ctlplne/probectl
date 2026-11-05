// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

func explorerIntegrationStore(t *testing.T, hooks ...func(*http.Client)) *ClickHouse {
	t.Helper()
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — Explorer real-store proof requires ClickHouse")
	}
	var control, reader *http.Client
	readerUser := ""
	if file := os.Getenv("PROBECTL_EXPLORER_TEST_CONTROL_AUTH_FILE"); file != "" {
		factory, err := crypto.LoadBasicAuthClientFactory(file)
		if err != nil {
			t.Fatal(err)
		}
		control, err = factory.HTTPClient(30*time.Second, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		factory, err = crypto.LoadBasicAuthClientFactory(os.Getenv("PROBECTL_EXPLORER_TEST_READER_AUTH_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		reader, err = factory.HTTPClient(30*time.Second, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		readerUser = factory.Username()
	} else {
		readerUser, reader = chtest.ProvisionReader(t, endpoint, "fx1_reader")
	}
	if directory := os.Getenv("PROBECTL_EXPLORER_TEST_DIAGNOSTICS"); directory != "" && reader != nil {
		next := reader.Transport
		if next == nil {
			next = http.DefaultTransport
		}
		reader.Transport = explorerDiagnosticTransport{next: next, directory: directory}
	}
	for _, hook := range hooks {
		hook(reader)
	}
	store, err := NewClickHouseWithClient(endpoint, 0, control)
	if err != nil {
		t.Fatal(err)
	}
	store.WithTenantScoping(true).WithReader(reader)
	if err := store.EnsureReaderRowPolicy(context.Background(), readerUser); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyReaderIsolation(context.Background(), readerUser); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestExplorerClickHouseRealOperatorBudgets(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-budget-red-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	first := explorerFixtureRow(red)
	second := first
	second.SrcPort++
	rows := []Row{first, second}
	for i := range 1000 {
		foreign := first
		foreign.TenantID, foreign.SrcPort = blue, uint16(i+1)
		rows = append(rows, foreign)
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: first.TS.Add(-time.Minute), To: first.TS.Add(time.Minute), View: "table", GroupBy: []string{"src_port"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	for _, kind := range []string{"rows", "bytes", "response", "memory", "groups", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			budget := DefaultExplorerBudget()
			want := ErrExplorerBudget
			switch kind {
			case "rows":
				budget.ReadRows = 1
			case "bytes":
				budget.ReadBytes = 1
			case "response":
				budget.ResponseBytes = 1
				want = chclient.ErrResponseTooLarge
			case "memory":
				budget.MemoryBytes = 1
			case "groups":
				budget.IntermediateGroups = 1
			case "deadline":
				budget.ExecutionLimit = time.Nanosecond
				want = context.DeadlineExceeded
			}
			if err := AttachExplorerBudget(store, budget); err != nil {
				t.Fatal(err)
			}
			result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: red, Plan: plan})
			if !errors.Is(err, want) || len(result.Rows) != 0 {
				t.Fatal("real reader cost refusal was not atomic or had the wrong cause", err)
			}
		})
	}
	budget := DefaultExplorerBudget()
	budget.ReadRows = 512
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: red, Plan: plan})
	if err != nil || len(result.Rows) != 2 {
		t.Fatal("foreign tenant partition consumed the own-tenant read budget", err)
	}
	if result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: blue, Plan: plan}); !errors.Is(err, ErrExplorerBudget) || len(result.Rows) != 0 {
		t.Fatal("large sibling query bypassed the same configured budget", err)
	}
	for range 6 {
		if result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: blue, Plan: plan}); err == nil || len(result.Rows) != 0 {
			t.Fatal("repeated over-budget query exposed records")
		}
	}
	if result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: red, Plan: plan}); err != nil || len(result.Rows) != 2 {
		t.Fatal("one tenant's normal cost refusals blocked a healthy sibling query", err)
	}
}

func TestExplorerClickHouseRealD102Plan(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	red := fmt.Sprintf("probectl-qa-beta-fx1-plan-red-%d", suffix)
	blue := fmt.Sprintf("probectl-qa-beta-fx1-plan-blue-%d", suffix)
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	first := explorerFixtureRow(red)
	first.BytesScaled = ^uint64(0)
	second := first
	second.TS = first.TS.Add(time.Minute)
	second.SrcPort++
	second.BytesScaled = 200
	tail := first
	tail.Protocol = "sflow"
	tail.DstPort = 80
	tail.BytesScaled = 20
	tail.SrcAddr = "203.0.113.9"
	foreign := first
	foreign.TenantID = blue
	foreign.BytesScaled = 987654321
	names := explorerNames{{TenantID: red, Exporter: first.Exporter, Index: 7, Name: "inside"}, {TenantID: red, Exporter: first.Exporter, Index: 8, Name: "outside"}}
	memory := NewMemory().WithExplorerInterfaces(names)
	store.WithExplorerInterfaces(names)
	for _, backend := range []Store{store, memory} {
		if err := backend.Insert(ctx, []Row{first, second, tail, foreign, first}); err != nil {
			t.Fatal(err)
		}
	}
	all := []flow.QueryMetric{}
	for _, definition := range flow.QueryMetricDefinitions() {
		for _, calc := range definition.Calculations {
			role := "additional"
			if len(all) == 0 {
				role = "primary"
			}
			all = append(all, flow.QueryMetric{Measure: definition.Name, Calculation: calc, Role: role})
		}
	}
	compare := func(t *testing.T, plan flow.QueryPlan, tenants ...string) {
		t.Helper()
		tenant := red
		if len(tenants) > 0 {
			tenant = tenants[0]
		}
		query := PlanQuery{TenantID: tenant, Plan: plan}
		reference := query
		if plan.DataSeries == "rollup" {
			reference.Plan.DataSeries = "raw"
		}
		want, err := memory.ExplorePlan(ctx, reference)
		if err != nil {
			t.Fatal(err)
		}
		if plan.DataSeries == "rollup" {
			want.Query.DataSeries = "rollup"
		}
		got, err := store.ExplorePlan(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		if (plan.DataSeries == "raw" || plan.DataSeries == "rollup") && got.Source != plan.DataSeries {
			t.Fatalf("explicit input source changed: requested=%s got=%s", plan.DataSeries, got.Source)
		}
		if got.Source == "rollup" {
			if got.Coverage == nil || !got.Coverage.CompleteInputs || got.ResolutionSeconds != 60 {
				t.Fatalf("complete retained coverage missing: %+v", got.Coverage)
			}
			want.Source = got.Source
			want.Coverage = got.Coverage
			want.ResolutionSeconds = got.ResolutionSeconds
		}
		if !reflect.DeepEqual(got, want) {
			g, _ := json.MarshalIndent(got, "", "  ")
			w, _ := json.MarshalIndent(want, "", "  ")
			t.Fatalf("plan SQL/reference differ\ngot=%s\nwant=%s", g, w)
		}
	}
	base := flow.QueryPlan{From: first.TS, To: first.TS.Add(20 * time.Minute), Metrics: all, GroupBy: []string{"protocol"}, RowLimit: 1, PageSize: 1}
	t.Run("all metric statistics with sparse zero buckets", func(t *testing.T) { compare(t, base) })
	for _, source := range []string{"raw", "rollup"} {
		for _, tenant := range []string{red, blue} {
			for _, metrics := range [][]flow.QueryMetric{
				{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "bps", Calculation: "avg", Role: "secondary"}, {Measure: "flows", Calculation: "total", Role: "additional"}},
				{{Measure: "bytes", Calculation: "p95", Role: "primary"}, {Measure: "bytes", Calculation: "p99", Role: "secondary"}, {Measure: "unique_src", Calculation: "bucket_total", Role: "additional"}},
				{{Measure: "unique_src", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "bucket_total", Role: "secondary"}, {Measure: "bytes", Calculation: "total", Role: "additional"}},
			} {
				t.Run(source+"/"+tenant+"/"+metrics[0].Measure+"/"+metrics[0].Calculation, func(t *testing.T) {
					plan := base
					plan.DataSeries = source
					plan.To = first.TS.Add(90 * time.Second)
					plan.Metrics = metrics
					compare(t, plan, tenant)
				})
			}
		}
	}
	t.Run("chart groups and Other", func(t *testing.T) {
		plan := base
		plan.View = "line"
		plan.SeriesDepth = 1
		plan.To = first.TS.Add(90 * time.Second)
		plan.Metrics = []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "bps", Calculation: "p95", Role: "secondary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}
		compare(t, plan)
	})
	t.Run("eight dimensions on each matrix axis", func(t *testing.T) {
		plan := base
		plan.View = "matrix"
		plan.GroupBy = []string{"src_addr", "src_port", "protocol", "exporter", "in_if", "vlan", "dscp", "src_asn"}
		plan.MatrixWith = []string{"dst_addr", "dst_port", "transport", "next_hop", "out_if", "net_type", "tcp_flags", "dst_country"}
		plan.Metrics = []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}
		compare(t, plan)
	})
	t.Run("nested filters with bound regex and operator values", func(t *testing.T) {
		plan := base
		plan.Filter = &flow.QueryFilterGroup{Match: "any", Groups: []flow.QueryFilterGroup{{Match: "all", Conditions: []flow.QueryPredicate{{Field: "src_as_name", Op: flow.QueryContains, Values: []string{"SOURCE"}}, {Field: "dst_port", Op: flow.QueryGreater, Values: []string{"400"}}, {Field: "tcp_flags", Op: flow.QueryBitAnd, Values: []string{"2"}}}}, {Mode: "exclude", Conditions: []flow.QueryPredicate{{Field: "protocol", Op: flow.QueryRegex, Values: []string{"^(ipfix|sflow)$"}}}}}}
		compare(t, plan)
	})
	for _, tenant := range []string{red, blue} {
		t.Run("sub-minute bucket paired "+tenant, func(t *testing.T) {
			plan := base
			plan.View = "line"
			plan.BucketSeconds = 1
			plan.Metrics = []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}
			compare(t, plan, tenant)
		})
		t.Run("monthly bucket paired "+tenant, func(t *testing.T) {
			plan := base
			plan.View = "line"
			plan.From = first.TS.AddDate(-2, 0, 0)
			plan.BucketSeconds = 30 * 86400
			plan.Metrics = []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}
			compare(t, plan, tenant)
		})
	}
	t.Run("published250 conditions and multiyear range", func(t *testing.T) {
		plan := base
		plan.From = first.TS.AddDate(-2, 0, 0)
		plan.BucketSeconds = 604800
		conditions := make([]flow.QueryPredicate, 250)
		for i := range conditions {
			conditions[i] = flow.QueryPredicate{Field: "dst_port", Op: flow.QueryGreater, Values: []string{"0"}}
		}
		plan.Filter = &flow.QueryFilterGroup{Conditions: conditions}
		plan.Metrics = []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}
		compare(t, plan)
	})
}

func TestExplorerClickHouseRealSnapshotClockUsesContributingInput(t *testing.T) {
	store := explorerIntegrationStore(t)
	red := fmt.Sprintf("probectl-qa-beta-fx1-clock-red-%d", time.Now().UnixNano())
	blue := red + "-sibling"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	matched := explorerFixtureRow(red)
	unmatched := matched
	unmatched.TS = matched.TS.Add(-24 * time.Hour)
	unmatched.DstPort = 80
	foreign := matched
	foreign.TenantID = blue
	foreign.TS = matched.TS.Add(-48 * time.Hour)
	if err := store.Insert(t.Context(), []Row{matched, unmatched, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: matched.TS.AddDate(-2, 0, 0), To: matched.TS.Add(time.Hour), BucketSeconds: 3600, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: red, Plan: plan})
	if err != nil || !result.OldestInput.Equal(matched.TS) {
		t.Fatalf("wrong contributing-input clock: %s %v", result.OldestInput, err)
	}
	plan.Filter.Conditions[0].Values = []string{"999"}
	result, err = store.ExplorePlan(t.Context(), PlanQuery{TenantID: red, Plan: plan})
	if err != nil || !result.OldestInput.IsZero() {
		t.Fatalf("empty query invented an input clock: %s %v", result.OldestInput, err)
	}
}

func TestExplorerClickHouseRealSnapshotInputsRecheckCoverageAndReader(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	red := fmt.Sprintf("probectl-qa-beta-fx1-snapshot-source-%d", time.Now().UnixNano())
	blue := red + "-sibling"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	row := explorerFixtureRow(red)
	sibling := row
	sibling.TenantID = blue
	if err := store.Insert(ctx, []Row{row, sibling}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: row.TS.Truncate(time.Hour), To: row.TS.Truncate(time.Hour).Add(time.Hour), BucketSeconds: 3600, GroupBy: []string{"src_port"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	query := func(tenant string, plan flow.QueryPlan) SnapshotInputs {
		t.Helper()
		result, err := store.ExplorePlan(ctx, PlanQuery{TenantID: tenant, Plan: plan})
		if err != nil {
			t.Fatal(err)
		}
		clock, err := snapshotInputsFor(result, flow.QueryVocabulary{})
		if err != nil {
			t.Fatal(err)
		}
		return clock
	}
	redClock, blueClock := query(red, plan), query(blue, plan)
	legacyPlan := plan
	legacyPlan.GroupBy = []string{"protocol"}
	legacyClock := query(red, legacyPlan)
	if err := store.VerifySnapshotInputs(ctx, red, redClock); err != nil {
		t.Fatal(err)
	}
	reader := store.reader
	store.reader = nil
	err := store.VerifySnapshotInputs(ctx, red, redClock)
	store.reader = reader
	if !errors.Is(err, chclient.ErrReaderRequired) {
		t.Fatalf("source validation bypassed mandatory reader: %v", err)
	}
	if err := store.DeleteTenantBefore(ctx, red, row.TS.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySnapshotInputs(ctx, red, redClock); err == nil {
		t.Fatal("old snapshot retained expired exact fields")
	}
	if err := store.VerifySnapshotInputs(ctx, red, legacyClock); err != nil {
		t.Fatalf("old hourly-compatible snapshot wrongly refused: %v", err)
	}
	if err := store.VerifySnapshotInputs(ctx, blue, blueClock); err != nil {
		t.Fatalf("source expiry crossed tenant scope: %v", err)
	}
}

// Test-only diagnostics remain in a private run-owned mount; production errors
// deliberately expose no SQL, metadata or literal values.
type explorerDiagnosticTransport struct {
	next      http.RoundTripper
	directory string
}

func (d explorerDiagnosticTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := d.next.RoundTrip(request)
	if err == nil && response.StatusCode >= 400 {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if readErr == nil {
			_ = os.WriteFile(filepath.Join(d.directory, fmt.Sprintf("clickhouse-%d.log", time.Now().UnixNano())), body, 0644)
			response.Body = io.NopCloser(bytes.NewReader(body))
		}
	}
	return response, err
}

func TestExplorerClickHouseRealD102FiftyThousandDetails(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	red := fmt.Sprintf("probectl-qa-beta-fx1-50k-red-%d", suffix)
	blue := fmt.Sprintf("probectl-qa-beta-fx1-50k-blue-%d", suffix)
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	base := explorerFixtureRow(red)
	rows := make([]Row, 50001)
	for i := 0; i < 50000; i++ {
		row := base
		row.SrcPort = uint16(i)
		row.BytesScaled = uint64(i + 1)
		rows[i] = row
	}
	rows[50000] = base
	rows[50000].TenantID = blue
	rows[50000].BytesScaled = ^uint64(0)
	if err := store.Insert(ctx, rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Minute), GroupBy: []string{"src_port"}, RowLimit: 50000, PageSize: 5000, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "packets", Calculation: "total", Role: "secondary"}, {Measure: "flows", Calculation: "total", Role: "secondary"}, {Measure: "bps", Calculation: "avg", Role: "secondary"}}}
	got, err := store.ExplorePlan(ctx, PlanQuery{TenantID: red, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 50000 || got.TotalGroups != 50000 || got.DetailLimited || got.Other != nil || got.Rows[0].Metrics["bytes:total"] != "50000" || got.Rows[49999].Metrics["bytes:total"] != "1" || got.Totals["bytes:total"] != "1250025000" {
		t.Fatalf("table reach/tenant scope: returned=%d total=%d limited=%v first=%v last=%v totals=%v", len(got.Rows), got.TotalGroups, got.DetailLimited, got.Rows[0], got.Rows[len(got.Rows)-1], got.Totals)
	}
	plan.View = "line"
	plan.RowLimit = 350
	plan.PageSize = 350
	plan.SeriesDepth = 40
	got, err = store.ExplorePlan(ctx, PlanQuery{TenantID: red, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 350 || len(got.Series) != 40 || len(got.OtherSeries) != 1 || !got.OtherSeries[0].Other || len(got.ChartRows) != 40 || got.ChartOther == nil || len(got.ChartRows[0].Metrics) != 4 || got.Totals["bytes:total"] != "1250025000" {
		t.Fatalf("chart reach/tenant scope: returned=%d series=%d totals=%v", len(got.Rows), len(got.Series), got.Totals)
	}
	if len(got.TotalSeries) != 1 || len(got.TotalSeries[0].Metrics) != 4 || got.TotalSeries[0].Metrics["bytes:total"] != "1250025000" || got.TotalSeries[0].Metrics["flows:total"] != "50000" {
		t.Fatalf("50k/four-metric total series: %+v", got.TotalSeries)
	}
}

func TestExplorerClickHouseRealD103MembershipAndMatrix(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	red := fmt.Sprintf("probectl-qa-beta-fx1-members-red-%d", suffix)
	blue := fmt.Sprintf("probectl-qa-beta-fx1-members-blue-%d", suffix)
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	base := explorerFixtureRow(red)
	a := base
	a.SrcAddr = "192.0.2.1"
	a.DstAddr = "198.51.100.1"
	a.Protocol = "A"
	a.BytesScaled = 90
	b := a
	b.TS = b.TS.Add(time.Minute)
	b.DstAddr = "198.51.100.2"
	b.BytesScaled = 10
	c := base
	c.TS = c.TS.Add(2 * time.Minute)
	c.SrcAddr = "192.0.2.2"
	c.DstAddr = "198.51.100.3"
	c.Protocol = "Other"
	c.BytesScaled = 99
	foreign := c
	foreign.TenantID = blue
	foreign.BytesScaled = 9000000
	memory := NewMemory()
	for _, backend := range []Store{memory, store} {
		if err := backend.Insert(ctx, []Row{a, b, c, foreign}); err != nil {
			t.Fatal(err)
		}
	}
	compare := func(query PlanQuery) {
		t.Helper()
		want, err := memory.ExplorePlan(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.ExplorePlan(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			t.Fatalf("membership/matrix SQL differs\ngot=%s\nwant=%s", g, w)
		}
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(3 * time.Minute), View: "line", GroupBy: []string{"protocol"}, RowLimit: 2, PageSize: 2, SeriesDepth: 1, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}, {Measure: "unique_src", Calculation: "bucket_total", Role: "secondary"}}}
	for _, selected := range [][][]string{{{"Other"}, {"A"}}, {{"missing"}}, {}} {
		compare(PlanQuery{TenantID: red, Plan: plan, SelectedGroups: selected})
	}
	plan.RowLimit = 1
	plan.PageSize = 1
	plan.SeriesDepth = 2
	compare(PlanQuery{TenantID: red, Plan: plan, SelectedGroups: [][]string{{"A"}}, SelectedChartGroups: [][]string{{"Other"}, {"A"}}})
	plan.RowLimit = 2
	plan.PageSize = 2
	plan.View = "matrix"
	plan.GroupBy = []string{"src_addr"}
	plan.MatrixWith = []string{"dst_addr"}
	plan.MatrixDepth = 1
	compare(PlanQuery{TenantID: red, Plan: plan})
	for _, selected := range [][][]string{{{"192.0.2.2"}, {"192.0.2.1"}}, {}} {
		for _, columns := range [][][]string{nil, {{"198.51.100.1"}}, {{"198.51.100.3"}}, {}} {
			compare(PlanQuery{TenantID: red, Plan: plan, SelectedGroups: selected, SelectedColumns: columns, SelectedMatrixRows: selected[:min(len(selected), plan.MatrixDepth)]})
		}
	}
}

func TestExplorerClickHouseRealD103EveryRegistryFieldPaired(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	red := fmt.Sprintf("probectl-qa-beta-fx1-reg2-red-%d", suffix)
	blue := fmt.Sprintf("probectl-qa-beta-fx1-reg2-blue-%d", suffix)
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	own := explorerFixtureRow(red)
	foreign := own
	foreign.TenantID = blue
	foreign.BytesScaled = 999999
	memory := NewMemory()
	for _, backend := range []Store{memory, store} {
		if err := backend.Insert(ctx, []Row{own, foreign, own}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{red, blue} {
		names := explorerNames{{TenantID: tenant, Exporter: own.Exporter, Index: 7, Name: "inside"}, {TenantID: tenant, Exporter: own.Exporter, Index: 8, Name: "outside"}}
		memory.WithExplorerInterfaces(names)
		store.WithExplorerInterfaces(names)
		for _, field := range flow.QueryFields() {
			t.Run(tenant+"/"+field.Name, func(t *testing.T) {
				plan := flow.QueryPlan{From: own.TS.Add(-time.Minute), To: own.TS.Add(time.Minute), GroupBy: []string{field.Name}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
				query := PlanQuery{TenantID: tenant, Plan: plan}
				reference, err := memory.ExplorePlan(ctx, query)
				if err != nil {
					t.Fatal(err)
				}
				if len(reference.Rows) != 1 {
					t.Fatalf("reference field missing %+v", reference)
				}
				value := reference.Rows[0].Group[field.Name]
				for _, op := range []flow.QueryOperator{"", flow.QueryEqual, flow.QueryNotEqual, flow.QueryIn, flow.QueryNotIn} {
					if op != "" {
						plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: field.Name, Op: op, Values: []string{value}}}}
					}
					query.Plan = plan
					want, err := memory.ExplorePlan(ctx, query)
					if err != nil {
						t.Fatal(err)
					}
					got, err := store.ExplorePlan(ctx, query)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("paired registry mismatch field=%s op=%s\ngot=%+v\nwant=%+v", field.Name, op, got, want)
					}
				}
			})
		}
	}
}

// A catch-up must never erase history whose raw input has already expired.
func TestExplorerClickHouseRealBackfillPreservesAgedHistory(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	red := fmt.Sprintf("probectl-qa-beta-fx1-backfill-red-%d", suffix)
	blue := fmt.Sprintf("probectl-qa-beta-fx1-backfill-blue-%d", suffix)
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	from := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i, tenant := range []string{red, blue} {
		if err := store.Insert(ctx, []Row{{TenantID: tenant, TS: from.Add(5 * time.Minute), Protocol: "nf5", Exporter: "retained", SrcAddr: "192.0.2.1", DstAddr: "203.0.113.1", Transport: "tcp", BytesScaled: uint64(41 + i), PacketsScaled: 2}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DeleteTenantBefore(ctx, red, from.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	before, err := store.hourlyRollups(ctx, red, from, from.Add(time.Hour))
	if err != nil || len(before) != 1 || before[0].Bytes != 41 {
		t.Fatalf("before catch-up=%+v err%v", before, err)
	}
	if err := store.backfillRollups(ctx, red, from, from.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err := store.hourlyRollups(ctx, red, from, from.Add(time.Hour))
	if err != nil || len(after) != 1 || after[0].Bytes != 41 {
		t.Fatalf("catch-up erased aged history: %+v err%v", after, err)
	}
	other, err := store.hourlyRollups(ctx, blue, from, from.Add(time.Hour))
	if err != nil || len(other) != 1 || other[0].Bytes != 42 {
		t.Fatalf("sibling history changed: %+v err%v", other, err)
	}
}

func TestExplorerClickHouseRealRetainedCoverage(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	red := fmt.Sprintf("probectl-qa-beta-fx1-retained-red-%d", suffix)
	blue := fmt.Sprintf("probectl-qa-beta-fx1-retained-blue-%d", suffix)
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	first := explorerFixtureRow(red)
	first.TS = first.TS.AddDate(-1, 0, 0)
	first.StartTS = first.TS.Add(-time.Second)
	first.BytesScaled = 9007199254740993
	second := first
	second.TS = first.TS.Add(time.Minute)
	second.SrcPort++
	second.BytesScaled = 7
	foreign := first
	foreign.TenantID = blue
	foreign.BytesScaled = 9999999
	memory := NewMemory()
	for _, backend := range []Store{store, memory} {
		if err := backend.Insert(ctx, []Row{first, second, foreign, first}); err != nil {
			t.Fatal(err)
		}
	}
	plan := flow.QueryPlan{From: first.TS.Add(-30 * time.Second), To: first.TS.Add(150 * time.Second), GroupBy: []string{"src_port", "src_asn", "dst_country", "exporter", "in_if", "vlan", "dscp", "protocol"}, View: "line", Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "bps", Calculation: "p95", Role: "secondary"}, {Measure: "unique_src_port", Calculation: "p99", Role: "secondary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}}
	compare := func(plan flow.QueryPlan, tenant string, wantSource string) {
		t.Helper()
		refPlan := plan
		refPlan.DataSeries = "raw"
		want, err := memory.ExplorePlan(ctx, PlanQuery{TenantID: tenant, Plan: refPlan})
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.ExplorePlan(ctx, PlanQuery{TenantID: tenant, Plan: plan})
		if err != nil {
			t.Fatal(err)
		}
		if got.Source != wantSource {
			t.Fatalf("source=%s want%s", got.Source, wantSource)
		}
		if wantSource == "rollup" && (got.Coverage == nil || !got.Coverage.CompleteInputs || got.ResolutionSeconds != 60) {
			t.Fatalf("coverage=%+v", got.Coverage)
		}
		want.Query.DataSeries = got.Query.DataSeries
		want.Source = got.Source
		want.Coverage = got.Coverage
		want.ResolutionSeconds = got.ResolutionSeconds
		if !reflect.DeepEqual(got, want) {
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			t.Fatalf("retained input differs\ngot%s\nwant%s", g, w)
		}
	}
	plan.DataSeries = "rollup"
	compare(plan, red, "rollup")
	if err := store.exec(ctx, "", "DELETE FROM "+sharedFlowsTable+" WHERE tenant_id={tenant:String} AND ts<{cutoff:DateTime64(3)} SETTINGS mutations_sync=2", chParams{"tenant": red, "cutoff": chTimeParam(first.TS.Add(24 * time.Hour))}, nil); err != nil {
		t.Fatal(err)
	}
	plan.DataSeries = "auto"
	compare(plan, red, "rollup")
	foreignPlan := plan
	foreignPlan.DataSeries = "rollup"
	compare(foreignPlan, blue, "rollup")
	raw := plan
	raw.DataSeries = "raw"
	if _, err := store.ExplorePlan(ctx, PlanQuery{TenantID: red, Plan: raw}); err == nil {
		t.Fatal("raw override silently lost aged input")
	} else {
		var coverage *PlanCoverageError
		if !errors.As(err, &coverage) {
			t.Fatalf("raw refusal=%v", err)
		}
	}
	// A v5-only row is real retained history with no invented v6 fields.
	old := first.TS.Add(-24 * time.Hour).Truncate(time.Hour)
	if err := store.exec(ctx, "", "INSERT INTO "+sharedFlowRollupsTable+" (tenant_id,bucket,protocol,exporter,src_addr,dst_addr,transport,row_id,bytes_scaled,packets_scaled,flow_count,subject_keys) VALUES ({tenant:String},{at:DateTime},'netflow5','old-router','198.51.100.8','203.0.113.1','tcp','v5-only',41,2,1,['legacy-subject'])", chParams{"tenant": red, "at": old.Format("2006-01-02 15:04:05")}, nil); err != nil {
		t.Fatal(err)
	}
	legacy := flow.QueryPlan{From: old, To: old.Add(time.Hour), DataSeries: "rollup", BucketSeconds: 3600, GroupBy: []string{"exporter"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}}
	got, err := store.ExplorePlan(ctx, PlanQuery{TenantID: red, Plan: legacy})
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "rollup" || got.Coverage == nil || got.Coverage.CompleteInputs || got.ResolutionSeconds != 3600 || got.Totals["bytes:total"] != "41" || got.Totals["unique_src:total"] != "1" {
		t.Fatalf("legacy coverage=%+v", got)
	}
	for _, changed := range []flow.QueryPlan{func() flow.QueryPlan { p := legacy; p.GroupBy = []string{"src_port"}; return p }(), func() flow.QueryPlan { p := legacy; p.BucketSeconds = 60; return p }(), func() flow.QueryPlan { p := legacy; p.From = p.From.Add(time.Minute); return p }()} {
		if _, err := store.ExplorePlan(ctx, PlanQuery{TenantID: red, Plan: changed}); err == nil {
			t.Fatal("fabricated legacy field/resolution")
		} else {
			var coverage *PlanCoverageError
			if !errors.As(err, &coverage) {
				t.Fatalf("legacy refusal=%v", err)
			}
		}
	}
	for _, lane := range []struct {
		tenant string
		count  int
	}{{red, 3}, {blue, 1}} {
		rows, err := store.queryScoped(ctx, Target{}, lane.tenant, "SELECT count() AS n FROM "+sharedFlowRollupsTable+" FINAL", nil)
		if err != nil || len(rows) != 1 || chCount(rows[0]["n"]) != int64(lane.count) {
			t.Fatalf("predicate-free retained reader %s: %+v %v", lane.tenant, rows, err)
		}
	}

	var retained bytes.Buffer
	if n, err := store.ExportRetainedTenant(ctx, red, &retained); err != nil || n != 3 {
		t.Fatalf("retained portability count=%d err%v", n, err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(retained.Bytes()), []byte{'\n'}) {
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row["tenant_id"] != red {
			t.Fatalf("foreign retained portability: %s", line)
		}
		if _, ok := row["coverage_version"]; !ok {
			t.Fatal("portability lost coverage marker")
		}
	}
	retained.Reset()
	if n, err := store.ExportRetainedSubject(ctx, red, first.AgentID, &retained); err != nil || n != 2 || !bytes.Contains(retained.Bytes(), []byte("9007199254740993")) {
		t.Fatalf("retained subject portability=%d %v", n, err)
	}
	retained.Reset()
	if n, err := store.ExportRetainedSubject(ctx, red, "legacy-subject", &retained); err != nil || n != 1 || !bytes.Contains(retained.Bytes(), []byte("v5-only")) {
		t.Fatalf("legacy subject portability=%d %v", n, err)
	}
	retained.Reset()
	if n, err := store.ExportRetainedSubject(ctx, blue, first.AgentID, &retained); err != nil || n != 1 || bytes.Contains(retained.Bytes(), []byte("9007199254740993")) {
		t.Fatalf("paired retained subject portability=%d %v", n, err)
	}
	if _, remaining, err := store.DeleteSubject(ctx, red, first.AgentID); err != nil || remaining != 0 {
		t.Fatalf("aged subject erasure=%d %v", remaining, err)
	}
	rows, err := store.query(ctx, "", "SELECT count() AS n FROM "+sharedFlowRollupsTable+" FINAL WHERE "+flowRollupSubjectPredicate(), chParams{"tenant": red, "subject": first.AgentID})
	if err != nil || len(rows) != 1 || chCount(rows[0]["n"]) != 0 {
		t.Fatalf("retained subject survived: %+v %v", rows, err)
	}
}

// Expiry between source selection and result delivery cannot turn a raw answer
// into a silently partial one. The same deadline covers the retained retry.
func TestExplorerClickHouseRealRetentionRace(t *testing.T) {
	var store *ClickHouse
	armed := false
	tenant := fmt.Sprintf("probectl-qa-beta-fx1-expiry-%d", time.Now().UnixNano())
	row := explorerFixtureRow(tenant)
	store = explorerIntegrationStore(t, func(client *http.Client) {
		next := client.Transport
		if next == nil {
			next = http.DefaultTransport
		}
		client.Transport = explorerRetentionTransport{next: next, fire: func() {
			if err := store.exec(t.Context(), "", "DELETE FROM "+sharedFlowsTable+" WHERE tenant_id={tenant:String} AND ts<{cutoff:DateTime64(3)} SETTINGS mutations_sync=2", chParams{"tenant": tenant, "cutoff": chTimeParam(row.TS.Add(time.Hour))}, nil); err != nil {
				t.Fatal(err)
			}
		}, armed: &armed}
	})
	t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, tenant) })
	if err := store.Insert(t.Context(), []Row{row}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: row.TS.Add(-time.Minute), To: row.TS.Add(time.Minute), GroupBy: []string{"src_port"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	armed = true
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if armed || result.Source != "rollup" || result.Totals["bytes:total"] != "12300" {
		t.Fatalf("retention race returned partial raw result: armed=%v result=%+v", armed, result)
	}
}

type explorerRetentionTransport struct {
	next  http.RoundTripper
	fire  func()
	armed *bool
}

func (t explorerRetentionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	response, err := t.next.RoundTrip(request)
	if err == nil && *t.armed && bytes.Contains(body, []byte("WITH filtered AS")) && bytes.Contains(body, []byte("FROM probectl_flows FINAL")) {
		content, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		response.Body = io.NopCloser(bytes.NewReader(content))
		*t.armed = false
		t.fire()
	}
	return response, err
}

func TestExplorerClickHouseRealRetentionClock(t *testing.T) {
	store := explorerIntegrationStore(t)
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	tenant := fmt.Sprintf("probectl-qa-beta-fx1-policy-%d", suffix)
	t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, tenant) })
	row := explorerFixtureRow(tenant)
	if err := store.Insert(ctx, []Row{row}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteTenantBefore(ctx, tenant, row.TS.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	from := row.TS.Truncate(time.Hour)
	plan := flow.QueryPlan{From: from, To: from.Add(time.Hour), BucketSeconds: 3600, GroupBy: []string{"exporter"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	result, err := store.ExplorePlan(ctx, PlanQuery{TenantID: tenant, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source != "rollup" || result.Coverage == nil || result.Coverage.CompleteInputs || result.Totals["bytes:total"] != "12300" {
		t.Fatalf("tenant expiry lost old hourly data or retained complete input: %+v", result)
	}
	plan.GroupBy = []string{"src_port"}
	if _, err := store.ExplorePlan(ctx, PlanQuery{TenantID: tenant, Plan: plan}); err == nil {
		t.Fatal("tenant policy left expired exact fields queryable")
	}
	rows, err := store.query(ctx, "", "SELECT agent_id,src_port,bytes,coverage_version FROM "+sharedFlowRollupsTable+" FINAL WHERE tenant_id={tenant:String}", chParams{"tenant": tenant})
	if err != nil || len(rows) != 1 || chToString(rows[0]["agent_id"]) != "" || chToUint64(rows[0]["src_port"]) != 0 || chToUint64(rows[0]["bytes"]) != 0 || chToUint64(rows[0]["coverage_version"]) != 0 {
		t.Fatalf("exact fields physically survived tenant expiry: %+v %v", rows, err)
	}
	// Prove actual column TTL on an exact run-owned empty structural copy.
	// It carries no other tenant data or query grants and is dropped afterward.
	table := fmt.Sprintf("probectl_qa_beta_fx1_ttl_%d", suffix)
	if err := store.exec(ctx, "", "CREATE TABLE "+table+" AS "+sharedFlowRollupsTable, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.exec(context.Background(), "", "DROP TABLE IF EXISTS "+table, nil, nil) })
	if err := store.configureFullRollupRetention(ctx, "", table, 1); err != nil {
		t.Fatal(err)
	}
	old := row.TS.AddDate(-1, 0, 0)
	if err := store.exec(ctx, "", "INSERT INTO "+table+" (tenant_id,bucket,protocol,exporter,src_addr,dst_addr,transport,row_id,bytes_scaled,packets_scaled,flow_count,subject_keys,agent_id,ts,src_port,bytes,coverage_version) VALUES ({tenant:String},{at:DateTime},'nf5','router','192.0.2.1','203.0.113.1','tcp','old',41,2,1,['private-agent'],'private-agent',{at:DateTime64(3)},443,99,1)", chParams{"tenant": tenant, "at": old.Format("2006-01-02 15:04:05")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.exec(ctx, "", "ALTER TABLE "+table+" MATERIALIZE TTL SETTINGS mutations_sync=2", nil, nil); err != nil {
		t.Fatal(err)
	}
	rows, err = store.query(ctx, "", "SELECT agent_id,src_port,bytes,coverage_version,bytes_scaled FROM "+table+" FINAL WHERE tenant_id={tenant:String}", chParams{"tenant": tenant})
	if err != nil || len(rows) != 1 || chToString(rows[0]["agent_id"]) != "" || chToUint64(rows[0]["src_port"]) != 0 || chToUint64(rows[0]["bytes"]) != 0 || chToUint64(rows[0]["coverage_version"]) != 0 || chToUint64(rows[0]["bytes_scaled"]) != 41 {
		t.Fatalf("column TTL failed to preserve only old hourly inputs: %+v %v", rows, err)
	}
	if err := store.configureFullRollupRetention(ctx, "", table, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.exec(ctx, "", "INSERT INTO "+table+" (tenant_id,bucket,protocol,exporter,src_addr,dst_addr,transport,row_id,bytes_scaled,packets_scaled,flow_count,agent_id,ts,src_port,bytes,coverage_version) VALUES ({tenant:String},{at:DateTime},'nf5','router','192.0.2.1','203.0.113.1','tcp','explicit-keep',42,2,1,'private-agent',{at:DateTime64(3)},443,99,1)", chParams{"tenant": tenant, "at": old.Format("2006-01-02 15:04:05")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.exec(ctx, "", "OPTIMIZE TABLE "+table+" FINAL", nil, nil); err != nil {
		t.Fatal(err)
	}
	rows, err = store.query(ctx, "", "SELECT agent_id,src_port,coverage_version FROM "+table+" FINAL WHERE tenant_id={tenant:String} AND row_id='explicit-keep'", chParams{"tenant": tenant})
	if err != nil || len(rows) != 1 || chToString(rows[0]["agent_id"]) != "private-agent" || chToUint64(rows[0]["src_port"]) != 443 || chToUint64(rows[0]["coverage_version"]) != 1 {
		t.Fatalf("explicit keep-forever did not remove the earlier column clock: %+v %v", rows, err)
	}
}

func TestExplorerClickHouseRealRawCoveragePaired(t *testing.T) {
	store := explorerIntegrationStore(t)
	suffix := fmt.Sprint(time.Now().UnixNano())
	red, blue := "probectl-qa-beta-raw-coverage-red-"+suffix, "probectl-qa-beta-raw-coverage-blue-"+suffix
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	own := explorerFixtureRow(red)
	other := own
	other.TenantID = blue
	other.BytesScaled = 999999
	if err := store.Insert(t.Context(), []Row{own, other}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{red, blue} {
		for _, source := range []string{"raw", "auto"} {
			result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: flow.QueryPlan{From: own.TS.Add(-time.Minute), To: own.TS.Add(time.Minute), DataSeries: source, GroupBy: []string{"src_addr"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}})
			if err != nil {
				t.Fatal(err)
			}
			if result.Source != "raw" || result.ResolutionSeconds != flow.MinPlanBucketSeconds || result.Coverage == nil || !result.Coverage.CompleteInputs || result.Coverage.ResolutionSeconds != flow.MinPlanBucketSeconds || !reflect.DeepEqual(result.Coverage.Fields, allPlanFields()) {
				t.Fatal("raw source omitted its complete retained input descriptor", tenant, source, result.Coverage, result.ResolutionSeconds)
			}
			expected := "12300"
			if tenant == blue {
				expected = "999999"
			}
			if len(result.Rows) != 1 || result.Totals["bytes:total"] != expected {
				t.Fatal("raw coverage query crossed tenant or changed exact data", tenant, source)
			}
		}
	}
}
