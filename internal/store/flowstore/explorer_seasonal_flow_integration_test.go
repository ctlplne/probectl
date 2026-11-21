// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSeasonalFlowWindowPlanUsesRealClickHouseTenantReader(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-seasonal-periods-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	plan, ends := checkSeasonalFlowWindowPlan(t, store, red, blue)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(red))
	budget := ExplorerQueryBudget(store)
	query := PlanQuery{TenantID: red, Plan: plan}
	var vocabulary flow.QueryVocabulary
	span, clocks, err := seasonalFlowPlan(ctx, query, ends, vocabulary, budget)
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.route(ctx, red)
	if err != nil {
		t.Fatal(err)
	}
	lane, err := store.readLane(target, red)
	if err != nil {
		t.Fatal(err)
	}
	table, err := tableFor(target)
	if err != nil {
		t.Fatal(err)
	}
	limited, err := buildSeasonalFlowSQL(ctx, budget, query, span, table, nil, vocabulary, clocks, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.explorerQueryRows(ctx, target, lane, red, limited.sql, limited.params, limited.clocks...)
	if !errors.Is(err, ErrExplorerBudget) || len(rows) != 0 {
		t.Fatal("overlapping memberships were not refused before returning groups", err)
	}
}

func TestSeasonalDDoSPreservesPinnedPortFilterOnClickHouse(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-ddos-port-projection-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	checkSeasonalDDoSSourcePortProjection(t, store, red, blue)
}

func TestSeasonalDDoSSeparatesOriginalCrossingIntervalsOnClickHouse(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-ddos-interval-projection-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	checkSeasonalDDoSClockProjection(t, store, red, blue)
}

func TestSeasonalDDoSRetainsScopedInvalidSamplingCountersOnClickHouse(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-ddos-interval-projection-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	checkSeasonalDDoSInvalidSamplingCounters(t, store, red, blue)
}

func TestSeasonalFlowDistantWindowsAvoidGapRowsOnTenantReader(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-short-intervals-%d", time.Now().UnixNano())
	blue := red + "-blue"
	current := time.Now().UTC().Add(-time.Minute).Truncate(5 * time.Second)
	ends := []time.Time{current.AddDate(0, 0, -7), current}
	for i, tenant := range []string{red, blue} {
		t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, tenant) })
		population := make([]Row, 0, 2050)
		for _, end := range ends {
			row := explorerFixtureRow(tenant)
			row.TS, row.StartTS = end.Add(-time.Second), end.Add(-2*time.Second)
			row.Protocol = "tcp"
			row.Bytes, row.BytesScaled = uint64(10+i), uint64(10+i)
			population = append(population, row)
		}
		anchor := current.AddDate(0, 0, -3)
		for n := range 2048 {
			row := explorerFixtureRow(tenant)
			row.TS, row.StartTS = anchor.Add(time.Duration(n)*time.Second), anchor.Add(time.Duration(n-1)*time.Second)
			row.Protocol = "tcp"
			row.Bytes, row.BytesScaled = 1000, 1000
			population = append(population, row)
		}
		if err := store.Insert(t.Context(), population); err != nil {
			t.Fatal(err)
		}
	}
	plan := flow.QueryPlan{From: current.Add(-5 * time.Second), To: current, View: "table", DataSeries: "raw",
		GroupBy: []string{"protocol"}, BucketSeconds: 1,
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	budget := ExplorerQueryBudget(store)
	budget.ReadRows = 256
	for i, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		query := PlanQuery{TenantID: tenant, Plan: plan}
		var vocabulary flow.QueryVocabulary
		span, clocks, err := seasonalFlowPlan(ctx, query, ends, vocabulary, budget)
		if err != nil {
			t.Fatal(err)
		}
		target, err := store.route(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		lane, err := store.readLane(target, tenant)
		if err != nil || !lane.Reader {
			t.Fatal("the protected windows have no scoped reader", err)
		}
		table, err := tableFor(target)
		if err != nil {
			t.Fatal(err)
		}
		read, err := buildSeasonalFlowSQL(ctx, budget, query, span, table, nil, vocabulary, clocks, budget.ReadRows, 0)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := store.explorerQueryRows(withExplorerBudget(ctx, budget), target, lane, tenant, read.sql, read.params, read.clocks...)
		if err != nil || len(rows) != 2 {
			t.Fatal("the two exact short windows lost their small read budget", len(rows), err)
		}
		source := planSource{kind: "raw", coverage: &PlanSourceCoverage{CompleteInputs: true, ResolutionSeconds: 1}}
		results, err := makeSeasonalWindowResults(ctx, span, clocks, source, query, vocabulary)
		if err != nil {
			t.Fatal(err)
		}
		members, err := decodeSeasonalFlowRows(ctx, results, rows, budget.ReadRows, 0, false, false)
		if err != nil || members != 2 {
			t.Fatal("the membership join saw a row outside the selected clocks", members, err)
		}
		for _, got := range results {
			if len(got.Rows) != 1 || got.Rows[0].Metrics["bytes:total"] != fmt.Sprint(10+i) {
				t.Fatal("a gap or sibling measurement reached the owned short window", tenant, got.Rows)
			}
		}
		windows, err := clocks.exactReadWindows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		withoutPruning := strings.Replace(read.sql, planSeasonalReadSQL("ts", windows, read.params), "", 1)
		if withoutPruning == read.sql {
			t.Fatal("the before-control still contains the storage time filter")
		}
		if _, err := store.explorerQueryRows(withExplorerBudget(ctx, budget), target, lane, tenant, withoutPruning, read.params, read.clocks...); !errors.Is(err, ErrExplorerBudget) {
			t.Fatal("the same query without the storage time filter should exhaust its read budget", err)
		}
	}
}
