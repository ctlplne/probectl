// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestExplorerAllocationsFollowCompleteActualPopulation(t *testing.T) {
	rows := []flowstore.PlanRow{
		{Group: map[string]string{"src_port": "1"}, Metrics: map[string]string{"bytes:total": "9007199254740993"}},
		{Group: map[string]string{"src_port": "2"}, Metrics: map[string]string{"bytes:total": "9007199254740994"}},
	}
	plan := flow.QueryPlan{GroupBy: []string{"src_port"}, RowLimit: int(^uint(0) >> 1), Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	selected, err := selectFlowComparisonGroups(rows, rows, plan)
	if err != nil || len(selected) != 2 || selected[0][0] != "2" || selected[1][0] != "1" {
		t.Fatal("representable requested reach changed complete actual population", err)
	}
	aligned, err := alignExactFlowComparison(rows, rows, plan.GroupBy, []string{"bytes:total"}, plan.RowLimit)
	if err != nil || len(aligned) != 2 {
		t.Fatal("safe allocation lost complete metric cells", err)
	}
	for _, row := range aligned {
		if row.CurrentExact == nil || row.PreviousExact == nil || *row.CurrentExact != *row.PreviousExact || row.DeltaExact == nil || *row.DeltaExact != "0" {
			t.Fatal("safe comparison allocation changed exact values")
		}
	}
	columns := explorerColumns(ai.ExplorerQuery{Dimensions: []string{"src_port", "src_port"}, Measures: []string{"bytes", "bytes"}, Visualization: "line"})
	if len(columns) != 3 || columns[0].Key != "occurred_at" || columns[1].Key != "src_port" || columns[2].Key != "bytes" {
		t.Fatal("column allocation changed deduplicated order")
	}
}
