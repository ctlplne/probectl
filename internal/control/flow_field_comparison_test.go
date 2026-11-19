// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCapturedFieldRanksUseTheCompleteCutoffUnderTenantScope(t *testing.T) {
	view := reportFlowSourceRef{ID: "owned-view", Version: "2"}
	settings := fieldComparisonSettings(view.ID, flow.FieldComparisonInput{Version: view.Version, Mode: "rank", TopKeys: 300,
		Measure: "bytes:total", MinimumRankChange: 1, MinimumChange: "1"})
	var captures [2]*reportFlowCapture
	var firstEntered string
	for i, tenant := range []string{"red", "blue"} {
		capture := fieldComparisonCapture(tenant, view, i == 0)
		captures[i] = capture
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		result, err := compareCapturedFlowFields(ctx, capture, settings, 8<<20)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if len(result.Changes) != 2 || result.Changes[0].Kind != "entered_top_set" || result.Changes[0].After.Rank != 300 ||
				result.Changes[0].Before != nil || result.Changes[0].Group["dst_port"] != "500" || result.Changes[1].Kind != "left_top_set" {
				t.Fatal("the complete source lost its real cutoff changes", result.Changes)
			}
			firstEntered = result.Changes[0].Key
		} else if len(result.Changes) != 0 {
			t.Fatal("the stable tenant borrowed changes from overlapping field names", result.Changes)
		}
		if firstEntered == "" {
			t.Fatal("no owned ranking change was captured")
		}
	}
	red := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	if result, err := compareCapturedFlowFields(red, captures[1], settings, 8<<20); !errors.Is(err, tenancy.ErrNoTenant) || len(result.Changes) != 0 {
		t.Fatal("a sibling capture reached field comparison", err)
	}
	latest := &captures[0].Results[1].Result
	latest.Rows[300].Metrics["bytes:total"] = latest.Rows[299].Metrics["bytes:total"]
	if result, err := compareCapturedFlowFields(red, captures[0], settings, 8<<20); !errors.Is(err, anomaly.ErrFlowFieldCoverage) || len(result.Changes) != 0 {
		t.Fatal("the tied cutoff was treated as complete evidence", err)
	}
}

func fieldComparisonCapture(tenant string, view reportFlowSourceRef, changed bool) *reportFlowCapture {
	from := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	paired := &reportFlowCapture{TenantID: tenant, SourceGeneration: 1, Inputs: make([]reportFlowInput, 2)}
	for period := range 2 {
		first := from.Add(time.Duration(period) * time.Minute)
		plan := flow.QueryPlan{From: first, To: first.Add(time.Minute), View: "table", RowLimit: 301,
			GroupBy: []string{"src_addr", "dst_port"},
			Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
		result := flowstore.PlanResult{Query: plan, Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true},
			OldestInput: first, TotalGroups: 301}
		for group := range 301 {
			port := group
			if changed && period == 1 && group == 299 {
				port = 500
			}
			result.Rows = append(result.Rows, flowstore.PlanRow{Group: map[string]string{"src_addr": "192.0.2.5", "dst_port": strconv.Itoa(port)},
				Metrics: map[string]string{"bytes:total": fmt.Sprint(1_000 - group)}})
		}
		paired.Results = append(paired.Results, capturedReportFlow{TenantID: tenant, ID: view.ID, Version: view.Version, Period: "current", Result: result})
	}
	return paired
}
