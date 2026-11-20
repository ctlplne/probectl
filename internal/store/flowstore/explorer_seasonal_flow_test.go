// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSeasonalFlowWindowPlanPreservesWholeTenantHistory(t *testing.T) {
	checkSeasonalFlowWindowPlan(t, NewMemory(), "red", "blue")
}

func TestSeasonalDDoSPreservesPinnedPortFilterUnderGroupBudget(t *testing.T) {
	checkSeasonalDDoSSourcePortProjection(t, NewMemory(), "red", "blue")
}

func checkSeasonalDDoSSourcePortProjection(t *testing.T, store Store, red, blue string) {
	t.Helper()
	const sourcePorts = 2048
	end := time.Now().UTC().Add(-time.Minute).Truncate(5 * time.Second)
	budget := ExplorerQueryBudget(store)
	budget.IntermediateGroups = 64
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range []string{red, blue} {
		amount := [...]uint64{5, 7}[lane]
		row := explorerFixtureRow(tenant)
		row.TS, row.StartTS = end.Add(-time.Second), end.Add(-2*time.Second)
		row.Bytes, row.BytesScaled = amount, amount
		row.Packets, row.PacketsScaled = 2, 2
		rows := make([]Row, 0, sourcePorts+1)
		for port := uint16(20_000); port < 20_000+sourcePorts; port++ {
			row.SrcPort = port
			rows = append(rows, row)
		}
		row.Transport, row.SrcPort = "udp", 53
		row.Bytes, row.BytesScaled = amount*3, amount*3
		rows = append(rows, row)
		if err := store.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	plan := flow.QueryPlan{From: end.Add(-5 * time.Second), To: end, View: "table", DataSeries: "raw", BucketSeconds: 1,
		GroupBy: []string{"dst_addr", "transport", "tcp_flags", "src_port", "sampling"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"},
			{Measure: "packets", Calculation: "total", Role: "additional"}, {Measure: "flows", Calculation: "total", Role: "additional"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryNotEqual, Values: []string{"20000"}}}}}
	for lane, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewPlanBatch(ctx, store, tenant, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(batch.Close)
		query := PlanQuery{TenantID: tenant, Plan: plan, DDoSSourcePortProjection: true}
		result, err := batch.ExploreSeasonalWindows(query, []time.Time{end}, 0)
		if err != nil || len(result) != 1 || len(result[0].Rows) != 2 {
			t.Fatal("the detector could not read the exact short-window population within the group budget", result, err)
		}
		totals := make(map[string]PlanRow)
		for _, row := range result[0].Rows {
			totals[row.Group["transport"]] = row
		}
		amount := [...]uint64{5, 7}[lane]
		if tcp, udp := totals["tcp"], totals["udp"]; tcp.Group["src_port"] != "0" || udp.Group["src_port"] != "53" ||
			tcp.Metrics["bytes:total"] != strconv.FormatUint(amount*(sourcePorts-1), 10) || tcp.Metrics["packets:total"] != strconv.Itoa(2*(sourcePorts-1)) ||
			tcp.Metrics["flows:total"] != strconv.Itoa(sourcePorts-1) || udp.Metrics["bytes:total"] != strconv.FormatUint(amount*3, 10) ||
			udp.Metrics["packets:total"] != "2" || udp.Metrics["flows:total"] != "1" {
			t.Fatal("projection changed filter membership, scoped totals or the original UDP association", totals)
		}
		query.DDoSSourcePortProjection = false
		if result, err := batch.ExploreSeasonalWindows(query, []time.Time{end}, 0); !errors.Is(err, ErrExplorerBudget) || result != nil {
			t.Fatal("the ordinary per-port read should exceed the same group budget", err)
		}
	}
}

func checkSeasonalFlowWindowPlan(t *testing.T, store Store, red, blue string) (flow.QueryPlan, []time.Time) {
	t.Helper()
	const periods = 42*24 + 1
	last := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Hour)
	ends := make([]time.Time, periods)
	for i := range ends {
		ends[i] = last.Add(-time.Duration(periods-1-i) * time.Hour)
	}
	laneValues := [2]uint64{9007199254740993, 100}
	for i, tenant := range []string{red, blue} {
		rows := make([]Row, 0, periods)
		for period, ending := range ends {
			if period == 1 || period == 2 {
				continue
			}
			row := explorerFixtureRow(tenant)
			row.TS, row.StartTS = ending.Add(-5*time.Minute), ending.Add(-5*time.Minute-time.Second)
			row.Protocol, row.Bytes, row.BytesScaled = "tcp", laneValues[i], laneValues[i]
			rows = append(rows, row)
		}
		if err := store.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	plan := flow.QueryPlan{From: last.Add(-70 * time.Minute), To: last, View: "table", DataSeries: "raw",
		GroupBy: []string{"protocol"}, BucketSeconds: 300, Metrics: []flow.QueryMetric{
			{Measure: "bytes", Calculation: "total", Role: "primary"},
			{Measure: "unique_src", Calculation: "total", Role: "secondary"},
		}}
	for i, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewPlanBatch(ctx, store, tenant, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(batch.Close)
		result, err := batch.ExploreSeasonalWindows(PlanQuery{TenantID: tenant, Plan: plan}, ends, 0)
		if err != nil || len(result) != periods {
			t.Fatalf("read %d of %d whole comparison periods: %v", len(result), periods, err)
		}
		for period, got := range result {
			if !got.Query.To.Equal(ends[period]) || got.Coverage == nil || !got.Coverage.CompleteInputs {
				t.Fatal("flow period lacked its complete input clock", period)
			}
			if period == 2 {
				if len(got.Rows) != 0 || !got.OldestInput.IsZero() {
					t.Fatal("absent flow input was synthesized", period)
				}
				continue
			}
			value := laneValues[i]
			oldest := ends[period].Add(-5 * time.Minute)
			if period != 0 && period != 3 {
				oldest = oldest.Add(-time.Hour)
			}
			if period > 3 {
				value *= 2
			}
			if len(got.Rows) != 1 || got.Rows[0].Group["protocol"] != "tcp" ||
				got.Rows[0].Metrics["bytes:total"] != strconv.FormatUint(value, 10) || got.Rows[0].Metrics["unique_src:total"] != "1" ||
				!got.OldestInput.Equal(oldest) {
				t.Fatalf("period %d lost exact scoped overlap, distinct members or coverage: %+v", period, got.Rows)
			}
		}
		foreign := []string{red, blue}[1-i]
		if rows, err := batch.ExploreSeasonalWindows(PlanQuery{TenantID: foreign, Plan: plan}, ends, 0); !errors.Is(err, ErrNoTenant) || rows != nil {
			t.Fatal("sibling tenant reached the seasonal plan reader", err)
		}
	}
	return plan, ends
}
