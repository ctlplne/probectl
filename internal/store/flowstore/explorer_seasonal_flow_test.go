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
