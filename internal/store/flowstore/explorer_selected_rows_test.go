// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

type selectedRowsCapacityStore interface {
	Store
	PlanStore
}

func proveCompleteSelectedRowCapacity(t *testing.T, memory selectedRowsCapacityStore, red, blue string) {
	t.Helper()
	const count = 50001
	budget := DefaultExplorerBudget()
	budget.ExecutionLimit = 30 * time.Second
	if err := AttachExplorerBudget(memory, budget); err != nil {
		t.Fatal(err)
	}
	base := explorerFixtureRow(red)
	rows := make([]Row, 0, 2*count)
	for _, tenant := range []string{red, blue} {
		for i := range count {
			row := base
			row.TenantID = tenant
			row.SrcPort = uint16(i)
			row.BytesScaled = uint64(i + 1)
			if tenant == blue {
				row.BytesScaled *= 2
			}
			rows = append(rows, row)
		}
	}
	if err := memory.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Minute), GroupBy: []string{"src_port"}, RowLimit: count, PageSize: 5000, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	for _, tenant := range []string{red, blue} {
		scale := uint64(1)
		if tenant == blue {
			scale = 2
		}
		result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: plan})
		if err != nil || len(result.Rows) != count || result.TotalGroups != count || result.DetailLimited || result.Other != nil || result.Totals["bytes:total"] != strconv.FormatUint(scale*count*(count+1)/2, 10) {
			t.Fatal("complete selected row quota or tenant totals changed", tenant, err)
		}
		for index, row := range result.Rows {
			if row.Group["src_port"] != strconv.Itoa(count-index-1) || row.Metrics["bytes:total"] != strconv.FormatUint(scale*uint64(count-index), 10) {
				t.Fatal("selected row membership lost exact tenant values", tenant, index)
			}
		}
	}
	plan.View = "line"
	plan.RowLimit = 351
	plan.PageSize = 351
	plan.SeriesDepth = 1
	chart, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: red, Plan: plan})
	if err != nil || len(chart.Rows) != 351 || len(chart.Series) != 1 {
		t.Fatal("chart detail quota still tied to plotted membership", err)
	}
}

func TestExplorerCompleteSelectedRowsPastFormerQuotaKeepTenantTotals(t *testing.T) {
	memory := NewMemory()
	proveCompleteSelectedRowCapacity(t, memory, "red", "blue")
	low := DefaultExplorerBudget()
	low.IntermediateGroups = 100
	if err := AttachExplorerBudget(memory, low); err != nil {
		t.Fatal(err)
	}
	base := explorerFixtureRow("red")
	plan := flow.QueryPlan{From: base.TS, To: base.TS.Add(time.Minute), GroupBy: []string{"src_port"}, RowLimit: 50001, PageSize: 5000}
	refused, err := memory.ExplorePlan(context.Background(), PlanQuery{TenantID: "red", Plan: plan})
	if !errors.Is(err, ErrExplorerBudget) || len(refused.Rows) != 0 {
		t.Fatal("small actual resource admission returned partial selected rows", err)
	}
}
