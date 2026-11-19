// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type goldenFieldRow struct {
	group string
	value string
}

type goldenFieldCase struct {
	name, field, mode, measure, kind string
	before, after                    []goldenFieldRow
	totals                           [2]string
	top                              int
}

func goldenFieldRankCase(name, field, original, retired, newValue string) goldenFieldCase {
	return goldenFieldCase{name: name, field: field, mode: "rank", measure: "bytes:total", kind: "entered_top_set", top: 2,
		before: []goldenFieldRow{{original, "9007199254740995"}, {retired, "1"}},
		after:  []goldenFieldRow{{original, "9007199254740995"}, {newValue, "9007199254740993"}, {retired, "1"}}}
}

func goldenFlowFieldCases() []goldenFieldCase {
	return []goldenFieldCase{
		goldenFieldRankCase("new source", "src_addr", "192.0.2.7", "192.0.2.8", "192.0.2.9"),
		goldenFieldRankCase("new destination", "dst_addr", "198.51.100.7", "198.51.100.8", "198.51.100.9"),
		goldenFieldRankCase("new country", "src_country", "US", "GB", "DE"),
		goldenFieldRankCase("new AS", "dst_asn", "64512", "64513", "64514"),
		{name: "port share shift", field: "dst_port", mode: "share", measure: "bytes:total", kind: "share_shift", top: 3,
			before: []goldenFieldRow{{"443", "100"}, {"53", "100"}, {"123", "100"}},
			after:  []goldenFieldRow{{"443", "190"}, {"53", "100"}, {"123", "100"}},
			totals: [2]string{"300", "390"}},
		{name: "transport share shift", field: "transport", mode: "share", measure: "bytes:total", kind: "share_shift", top: 3,
			before: []goldenFieldRow{{"tcp", "100"}, {"udp", "100"}, {"icmp", "100"}},
			after:  []goldenFieldRow{{"tcp", "190"}, {"udp", "100"}, {"icmp", "100"}},
			totals: [2]string{"300", "390"}},
		{name: "destination fan-out", field: "src_addr", mode: "fanout", measure: "unique_dst:total", kind: "fanout_increase", top: 2,
			before: []goldenFieldRow{{"192.0.2.7", "3"}, {"192.0.2.8", "1"}},
			after:  []goldenFieldRow{{"192.0.2.7", "7"}, {"192.0.2.8", "1"}}},
	}
}

func TestGoldenFieldChangesAndNormalWeeklyClock(t *testing.T) {
	const tenant = "25ebf92b-c387-451d-9e67-0b323c402a58"
	const sibling = "aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"
	const rule = "18df565b-2523-443a-b139-eab57d6c0f79"
	view := reportFlowSourceRef{ID: "548baa36-4c4a-47a1-b7d8-7c7f48d36716", Version: "7"}
	owned := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	other := tenancy.WithTenant(t.Context(), tenancy.ID(sibling))
	replayClock := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)
	budget := alert.QueryGroupBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}

	for _, item := range goldenFlowFieldCases() {
		t.Run(item.name, func(t *testing.T) {
			input := flow.FieldComparisonInput{Version: view.Version, Mode: item.mode, Measure: item.measure, Cadence: "previous_week", PeriodSeconds: 300, TopKeys: item.top}
			switch item.mode {
			case "rank":
				input.MinimumChange = "100"
			case "share":
				input.ShareBasisPoints = 1000
			case "fanout":
				input.MinimumChange = "4"
			}
			settings := fieldComparisonSettings(view.ID, input)
			if err := settings.Validate(); err != nil {
				t.Fatal(err)
			}
			binding := alert.QueryGroupBinding{TenantID: tenant, RuleID: rule, ViewID: view.ID, ViewVersion: view.Version,
				Condition: alert.QueryCondition{Mode: alert.FieldChangeCondition, Field: &settings.FieldComparisonInput}}
			var state alert.QueryGroupState
			for hour := range 24 * 7 {
				at := replayClock.Add(time.Duration(hour) * time.Hour)
				stable := goldenNormalWeeklyWindow(item, hour)
				comparison, err := compareGoldenFieldWindows(owned, tenant, view, settings, stable, at)
				if err != nil || len(comparison.Changes) != 0 {
					t.Fatal("normal weekly source clocks raised a field change", hour, err)
				}
				events, next, err := alert.EvaluateFieldEpisodes(owned, binding, state, comparison, budget)
				if err != nil || len(events) != 0 {
					t.Fatal("normal weekly source clocks published a field episode", hour, err)
				}
				state = next
			}
			at := replayClock.Add(7 * 24 * time.Hour)
			comparison, err := compareGoldenFieldWindows(owned, tenant, view, settings, item, at)
			if err != nil || len(comparison.Changes) != 1 || comparison.Changes[0].Kind != item.kind {
				t.Fatal("planted field change was lost or duplicated", comparison.Changes, err)
			}
			event, next, err := alert.EvaluateFieldEpisodes(owned, binding, state, comparison, budget)
			if err != nil || len(event) != 1 || event[0].Change.After == nil || event[0].Change.After.Citation == "" {
				t.Fatal("planted field episode lost its after observation", event, err)
			}
			if item.mode != "rank" && (event[0].Change.Before == nil || event[0].Change.Before.Citation == "") {
				t.Fatal("observed field movement lost its before value")
			}
			if duplicate, _, err := alert.EvaluateFieldEpisodes(owned, binding, next, comparison, budget); !errors.Is(err, alert.ErrQueryGroups) || len(duplicate) != 0 {
				t.Fatal("a late reread of the committed window changed its episode", err)
			}
			replay, err := compareGoldenFieldWindows(owned, tenant, view, settings, item, at.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			stillActive, _, err := alert.EvaluateFieldEpisodes(owned, binding, next, replay, budget)
			if err != nil || len(stillActive) != 0 {
				t.Fatal("a sustained field change became a second episode", stillActive, err)
			}
			if event, _, err := alert.EvaluateFieldEpisodes(other, binding, state, comparison, budget); err == nil || len(event) != 0 {
				t.Fatal("a foreign context evaluated owned evidence", err)
			}
		})
	}
}

func goldenNormalWeeklyWindow(item goldenFieldCase, hour int) goldenFieldCase {
	// Weekdays and hours vary. The reference week has the same measured cycle.
	factor := big.NewInt(int64(1 + (hour/24)%3 + (hour%24)/6))
	scale := func(text string) string {
		value, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return text
		}
		return value.Mul(value, factor).String()
	}
	stable := item
	stable.before = make([]goldenFieldRow, len(item.before))
	for i, row := range item.before {
		stable.before[i] = goldenFieldRow{row.group, scale(row.value)}
	}
	stable.after = stable.before
	stable.totals[0] = scale(item.totals[0])
	stable.totals[1] = stable.totals[0]
	return stable
}

func compareGoldenFieldWindows(ctx context.Context, tenant string, view reportFlowSourceRef, settings flowFieldComparisonSettings, item goldenFieldCase, at time.Time) (flow.FieldComparison, error) {
	windows, err := anomaly.FlowFieldCompletedWindows(at, anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		return flow.FieldComparison{}, err
	}
	measure, calculation, _ := strings.Cut(item.measure, ":")
	capture := &reportFlowCapture{TenantID: tenant, SourceGeneration: 1, Inputs: make([]reportFlowInput, 2)}
	for i, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		rows := item.before
		if i == 1 {
			rows = item.after
		}
		plan := flow.QueryPlan{From: window.Start, To: window.End, View: "table", RowLimit: item.top + 1, GroupBy: []string{item.field},
			Metrics: []flow.QueryMetric{{Measure: measure, Calculation: calculation, Role: "primary"}}}
		result := flowstore.PlanResult{Query: plan, Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}, Source: "raw", ResolutionSeconds: 1,
			OldestInput: window.Start.Add(time.Second), TotalGroups: len(rows), Totals: map[string]string{item.measure: item.totals[i]}}
		for _, row := range rows {
			result.Rows = append(result.Rows, flowstore.PlanRow{Group: map[string]string{item.field: row.group}, Metrics: map[string]string{item.measure: row.value}})
		}
		capture.Results = append(capture.Results, capturedReportFlow{TenantID: tenant, ID: view.ID, Version: view.Version, Period: "current", Result: result})
	}
	return compareCapturedFlowFields(ctx, capture, settings, 8<<20)
}
