// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFieldHourlyHistoryConsidersEveryOriginalClock(t *testing.T) {
	const tenant = "25ebf92b-c387-451d-9e67-0b323c402a58"
	const sibling = "aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"
	const view = "548baa36-4c4a-47a1-b7d8-7c7f48d36716"
	const measure = "bytes:total"
	cases := []struct {
		cadence anomaly.FlowFieldComparisonCadence
		hours   int
	}{{anomaly.FlowFieldHourlyWeek, 168}, {anomaly.FlowFieldHourlyMonth, 672}}
	for _, test := range cases {
		t.Run(string(test.cadence), func(t *testing.T) {
			at := time.Date(2026, 1, 30, 5, 50, 0, 0, time.UTC)
			clocks, err := anomaly.FlowFieldCompletedWindows(at, test.cadence, 3600)
			if err != nil || clocks.History.Samples != test.hours || clocks.History.End.Sub(clocks.History.Start) != time.Duration(test.hours)*time.Hour ||
				!clocks.History.End.Equal(at.Truncate(time.Hour).Add(-time.Hour)) {
				t.Fatal("the complete baseline must end before the current UTC hour", clocks, err)
			}
			settings := fieldComparisonSettings(view, flow.FieldComparisonInput{Version: "7", Mode: "rank", Cadence: string(test.cadence), PeriodSeconds: 3600,
				Measure: measure, TopKeys: 2, MinimumChange: "100"})
			if err := settings.Validate(); err != nil {
				t.Fatal(err)
			}
			owned := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			other := tenancy.WithTenant(t.Context(), tenancy.ID(sibling))
			capture := historicalFieldCapture(tenant, settings.View, clocks)
			result, err := compareHistoricalFlowFields(owned, capture, settings, clocks, 8<<20)
			if err != nil || result.History == nil || result.History.Hours != test.hours || len(result.Changes) != 1 ||
				result.Changes[0].Kind != "entered_top_set" || result.Changes[0].Group["dst_port"] != "853" ||
				result.Changes[0].After == nil || result.Changes[0].After.Value != "9007199254740993" ||
				result.After.LastIncluded != "800" || result.After.FirstExcluded != "400" {
				t.Fatal("the cohort lost exact new membership or omitted the earliest hour", result, err)
			}
			if result, err := compareHistoricalFlowFields(other, capture, settings, clocks, 8<<20); !errors.Is(err, tenancy.ErrNoTenant) || len(result.Changes) != 0 {
				t.Fatal("the sibling could read owned hourly membership", err)
			}
			middle := &capture.Results[test.hours/2].Result
			recorded := middle.OldestInput
			middle.OldestInput = time.Time{}
			if result, err := compareHistoricalFlowFields(owned, capture, settings, clocks, 8<<20); !errors.Is(err, anomaly.ErrFlowFieldCoverage) || len(result.Changes) != 0 {
				t.Fatal("one missing hour cannot establish new membership", err)
			}
			middle.OldestInput = recorded
			middle.Rows[2].Metrics[measure] = middle.Rows[1].Metrics[measure]
			if result, err := compareHistoricalFlowFields(owned, capture, settings, clocks, 8<<20); !errors.Is(err, anomaly.ErrFlowFieldCoverage) || len(result.Changes) != 0 {
				t.Fatal("an unresolved historical tie cannot establish new membership", err)
			}
		})
	}
}

func historicalFieldCapture(tenant string, ref reportFlowSourceRef, clocks anomaly.FlowFieldComparisonClocks) *reportFlowCapture {
	const measure = "bytes:total"
	row := func(port, bytes string) flowstore.PlanRow {
		return flowstore.PlanRow{Group: map[string]string{"dst_port": port}, Metrics: map[string]string{measure: bytes}}
	}
	capture := &reportFlowCapture{TenantID: tenant, SourceGeneration: 1}
	for i, end := range clocks.Ends() {
		start := end.Add(-time.Hour)
		result := flowstore.PlanResult{Query: flow.QueryPlan{From: start, To: end, View: "table", RowLimit: 3, GroupBy: []string{"dst_port"},
			Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}},
			Source: "raw", ResolutionSeconds: 60, Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}, OldestInput: start.Add(time.Second), TotalGroups: 3,
			Rows: []flowstore.PlanRow{row("443", "400"), row("53", "200"), row("123", "10")}}
		if i == 0 {
			result.Rows[1] = row("8443", "300")
		}
		if i == clocks.History.Samples {
			result.Rows = []flowstore.PlanRow{row("853", "9007199254740993"), row("8443", "800"), row("443", "400")}
		}
		capture.Results = append(capture.Results, capturedReportFlow{TenantID: tenant, ID: ref.ID, Version: ref.Version, Period: "current", Result: result})
		capture.Inputs = append(capture.Inputs, reportFlowInput{ID: ref.ID, Version: ref.Version, Period: "current", From: start, To: end})
	}
	return capture
}
