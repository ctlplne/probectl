// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestFlowComparisonConfiguredAllocationRefusesWithoutPartialRows(t *testing.T) {
	rows := []flowstore.PlanRow{{Group: map[string]string{"src_port": "1"}, Metrics: map[string]string{"bytes:total": "9007199254740993"}}, {Group: map[string]string{"src_port": "2"}, Metrics: map[string]string{"bytes:total": "9007199254740994"}}}
	plan := flow.QueryPlan{GroupBy: []string{"src_port"}, RowLimit: 10, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	low := flowstore.DefaultExplorerBudget()
	low.MemoryBytes = 1
	aligned, err := alignExactFlowComparison(rows, rows, plan.GroupBy, []string{"bytes:total"}, plan.RowLimit, low)
	var domain *apierror.Error
	if aligned != nil || !errors.As(err, &domain) || domain.Code != string(apierror.CodeFlowQueryBudget) {
		t.Fatal("comparison cost refusal exposed data or lost its actionable code", err)
	}
	packed, err := packFlowComparisonRows(rows, rows, plan, low)
	if packed != nil || !errors.Is(err, flowstore.ErrExplorerBudget) {
		t.Fatal("comparison snapshot packing ignored its allocation budget", err)
	}
	if !errors.As(flowSnapshotError(err), &domain) || domain.Code != string(apierror.CodeFlowQueryBudget) {
		t.Fatal("packing cost refusal became a generic storage failure")
	}
	higher := flowstore.DefaultExplorerBudget()
	aligned, err = alignExactFlowComparison(rows, rows, plan.GroupBy, []string{"bytes:total"}, plan.RowLimit, higher)
	if err != nil || len(aligned) != 2 {
		t.Fatal("higher operator admission did not preserve the same selected rows", err)
	}
	packed, err = packFlowComparisonRows(rows, rows, plan, higher)
	if err != nil || len(packed) != 2 {
		t.Fatal("higher packing budget narrowed the valid query", err)
	}
}
