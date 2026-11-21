// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type weeklyDDoSHoldout struct {
	Name     string
	Positive bool
	Vector   bool
	Spread   bool
	// Application scenarios use the same growing flow records and differ
	// only in the completed, independently observed HTTP cohort.
	Application string
	// Counter values are percentages of normal demand. Zero represents an
	// unobserved window. References are stored newest first in the manifest.
	History [4][2]int
	Current [2]int
}

func weeklyDDoSHoldoutCases() []weeklyDDoSHoldout {
	growingHistory := [4][2]int{{116, 118}, {99, 102}, {92, 94}, {85, 87}}
	growingCurrent := [2]int{130, 132}
	return []weeklyDDoSHoldout{
		{Name: "pressure_after_recent_pressure", Positive: true, History: [4][2]int{{180, 185}, {100, 105}, {103, 104}, {99, 102}}, Current: [2]int{180, 185}},
		{Name: "normal_demand_after_recent_dip", History: [4][2]int{{45, 48}, {100, 105}, {101, 103}, {98, 100}}, Current: [2]int{104, 107}},
		{Name: "normal_growth_across_weeks_without_app", History: growingHistory, Current: growingCurrent},
		{Name: "pressure_indistinguishable_from_weekly_growth", Positive: true, History: growingHistory, Current: growingCurrent},
		{Name: "pressure_above_the_weekly_growth_band", Positive: true, History: growingHistory, Current: [2]int{155, 162}},
		{Name: "specific_vector_within_the_weekly_growth_band", Positive: true, Vector: true, History: growingHistory, Current: growingCurrent},
		{Name: "ordinary_spread_within_the_weekly_growth_band", Spread: true, History: growingHistory, Current: growingCurrent},
		{Name: "pressure_indistinguishable_from_ordinary_spread", Positive: true, Spread: true, History: growingHistory, Current: growingCurrent},
		{Name: "spread_above_the_weekly_growth_band", Positive: true, Spread: true, History: growingHistory, Current: [2]int{155, 162}},
		{Name: "normal_growth_across_weeks_with_healthy_app", Application: "healthy", History: growingHistory, Current: growingCurrent},
		{Name: "pressure_across_weeks_with_degraded_app", Positive: true, Application: "degraded", History: growingHistory, Current: growingCurrent},
		{Name: "pressure_across_weeks_with_missing_app", Positive: true, Application: "missing", History: growingHistory, Current: growingCurrent},
		{Name: "pressure_with_one_old_window_missing", Positive: true, History: [4][2]int{{100, 105}, {102, 0}, {101, 103}, {98, 100}}, Current: [2]int{176, 192}},
		{Name: "pressure_with_two_incomplete_weeks", Positive: true, History: [4][2]int{{100, 105}, {102, 0}, {0, 103}, {98, 100}}, Current: [2]int{176, 192}},
		{Name: "pressure_with_current_window_missing", Positive: true, History: [4][2]int{{100, 105}, {102, 105}, {101, 103}, {98, 100}}, Current: [2]int{176, 0}},
	}
}

func TestSyntheticDDoSChangingWeeklyBaselineHoldout(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	cases := weeklyDDoSHoldoutCases()
	periods := [...]int{5, 10}
	const variants = 8
	manifest, err := json.Marshal(struct {
		Epoch    time.Time
		Cases    []weeklyDDoSHoldout
		Periods  [2]int
		Variants int
	}{benchmarkDDoSEpoch, cases, periods, variants})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("weekly_holdout_manifest_sha256=%s scenario_variants=%d", hex.EncodeToString(crypto.Hash(manifest)), len(cases)*len(periods)*variants)
	for _, mode := range []string{"", flow.DDoSReferenceWeeklyRepresentative} {
		var counts benchmarkDDoSCounts
		for _, scenario := range cases {
			for _, period := range periods {
				for variant := range variants {
					outcome, week, err := replayWeeklyDDoSHoldout(ctx, scenario, period, variant, mode)
					if err != nil && !outcome.Abstained {
						t.Fatalf("%s mode=%q period=%d variant=%d: %v", scenario.Name, mode, period, variant, err)
					}
					counts.record(scenario.Positive, outcome)
					t.Logf("case=%s/%02d mode=%q window_seconds=%d positive=%t class=%q coverage_unknown=%t demand_explained=%t reference_weeks_ago=%d",
						scenario.Name, variant, mode, period, scenario.Positive, outcome.Class, outcome.Abstained, outcome.DemandProven, week)
					checkWeeklyDDoSHoldoutControls(t, scenario.Name, mode, outcome)
				}
			}
		}
		t.Logf("mode=%q true_positive=%d false_positive=%d true_negative=%d false_negative=%d abstained_positive=%d abstained_negative=%d",
			mode, counts.TruePositive, counts.FalsePositive, counts.TrueNegative, counts.FalseNegative, counts.AbstainedPositive, counts.AbstainedNegative)
	}
}

func checkWeeklyDDoSHoldoutControls(t *testing.T, name, mode string, outcome benchmarkDDoSOutcome) {
	t.Helper()
	weekly := mode == flow.DDoSReferenceWeeklyRepresentative
	switch name {
	case "pressure_after_recent_pressure":
		if weekly && (outcome.Abstained || outcome.Class == "") {
			t.Error("a single unusual reference week hid independently sustained pressure")
		}
	case "normal_demand_after_recent_dip":
		if weekly && (outcome.Abstained || outcome.Class != "") {
			t.Error("a preceding traffic dip caused an alarm for ordinary demand")
		}
	case "normal_growth_across_weeks_without_app", "pressure_indistinguishable_from_weekly_growth",
		"ordinary_spread_within_the_weekly_growth_band", "pressure_indistinguishable_from_ordinary_spread":
		if weekly && (!outcome.Abstained || outcome.Class != "" || outcome.DemandProven) {
			t.Error("matched flow-only growth needs independent corroboration before classification")
		}
	case "pressure_above_the_weekly_growth_band":
		if outcome.Abstained || outcome.Class != anomaly.DDoSVolumetric {
			t.Error("new pressure that exceeds the measured growth band should retain its finding")
		}
	case "specific_vector_within_the_weekly_growth_band":
		if outcome.Abstained || outcome.Class != anomaly.DDoSSYN {
			t.Error("independent SYN pressure should qualify during a continuing volume trend")
		}
	case "spread_above_the_weekly_growth_band":
		if outcome.Abstained || outcome.Class != anomaly.DDoSPrefixSpread {
			t.Error("accelerating pressure across protected destinations lost its classification")
		}
	case "normal_growth_across_weeks_with_healthy_app":
		if outcome.Abstained || outcome.Class != "" || (weekly && !outcome.DemandProven) {
			t.Error("proportionate healthy demand did not explain the growing listener")
		}
	case "pressure_across_weeks_with_degraded_app":
		if weekly && (outcome.Abstained || outcome.Class == "" || outcome.DemandProven) {
			t.Error("the identical flow increase was dismissed despite independently observed application degradation")
		}
	case "pressure_across_weeks_with_missing_app":
		if weekly && (!outcome.Abstained || outcome.Class != "" || outcome.DemandProven) {
			t.Error("the detector inferred demand or an episode without the bound application observation")
		}
	case "pressure_with_one_old_window_missing":
		if outcome.Abstained || outcome.Class == "" {
			t.Error("an older partial pair hid sustained pressure despite sufficient remaining pairs")
		}
	case "pressure_with_two_incomplete_weeks":
		if weekly && !outcome.Abstained {
			t.Error("two complete historical pairs established a representative week")
		}
	case "pressure_with_current_window_missing":
		if !outcome.Abstained {
			t.Error("an unobserved current interval established an episode or a quiet window")
		}
	}
}

func replayWeeklyDDoSHoldout(ctx context.Context, scenario weeklyDDoSHoldout, seconds, variant int, mode string) (benchmarkDDoSOutcome, int, error) {
	input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.7/32", Direction: "ingress", PeriodSeconds: seconds,
		ReferenceMode: mode, BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
		VectorShareBasisPoints: 6000, MinObservedRecords: 50, MinObservedAddresses: 2}
	if variant%2 != 0 {
		input.Prefix = "2001:db8::7/128"
	}
	if variant%4 >= 2 {
		input.Direction = "egress"
	}
	if scenario.Spread {
		input.Direction, input.Prefix = "ingress", "192.0.2.0/24"
		if variant%2 != 0 {
			input.Prefix = "2001:db8::/64"
		}
	}
	if scenario.Application != "" {
		input.Direction = "ingress"
		input.Application = &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}
	}
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, input)
	if err != nil {
		return benchmarkDDoSOutcome{}, 0, err
	}
	period := time.Duration(seconds) * time.Second
	end := benchmarkDDoSEpoch.Add(time.Duration(variant+2) * period)
	clocks, err := ddosClocks(end, seconds)
	if err != nil {
		return benchmarkDDoSOutcome{}, 0, err
	}
	basePackets := (4000 + 61*variant) * seconds / 5
	baseFrameSize := 80 + 11*variant
	weeks := input.ReferenceWeeks()
	capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1}
	appSpans := make(map[time.Time][]otelstore.Span)
	for index, windowEnd := range ddosReferenceEnds(weeks, clocks.Previous, clocks.Current) {
		week, half := weeks-index/2, index%2
		percent := scenario.Current[half]
		if week > 0 {
			percent = scenario.History[week-1][half]
		}
		var rows []flowstore.PlanRow
		if percent > 0 {
			packets := basePackets * percent / 100
			window := benchmarkDDoSWindow{Packets: packets, Bytes: packets * baseFrameSize, Records: 64 + variant, Addresses: 1, Sampling: 1}
			if week == 0 && scenario.Vector {
				window.Profile = "syn"
			}
			if week == 0 && scenario.Spread {
				window.Addresses = 4
			}
			rows = benchmarkDDoSRows(window)
			address := settings.Target.Addr()
			if scenario.Spread {
				address = address.Next()
			}
			for _, row := range rows {
				row.Group[settings.SideField] = address.String()
				address = address.Next()
			}
		}
		from := windowEnd.Add(-period)
		if input.Application != nil && (week != 0 || half != 1 || scenario.Application != "missing") {
			app := benchmarkDDoSApplication{Requests: percent * (2 + variant%3), LatencyMS: 18 + variant%4}
			if week == 0 && scenario.Application == "degraded" {
				app.Failures = app.Requests / 5
				app.LatencyMS *= 4
			}
			spans := benchmarkDDoSAppSpans(app, from)
			for i := range spans {
				spans[i].Attrs["network.local.address"] = settings.Target.Addr().String()
			}
			appSpans[from] = spans
		}
		capture.Results = append(capture.Results, capturedReportFlow{ID: settings.View.ID, Version: settings.View.Version, TenantID: benchmarkDDoSTenant,
			Result: flowstore.PlanResult{OldestInput: from, Source: "raw", ResolutionSeconds: 1,
				Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}, Query: flow.QueryPlan{View: "table", From: from, To: windowEnd}, Rows: rows}})
	}
	if binding := settings.Input.Application; binding != nil {
		settings.readApplication = func(ctx context.Context, source anomaly.DDoSObservation) (anomaly.DDoSApplicationWindow, bool, error) {
			return projectDDoSApplicationWindow(ctx, source, binding.Service, binding.Port, source.To, appSpans[source.From])
		}
	}
	matches, err := ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current)
	if err != nil {
		return benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage)}, 0, err
	}
	var assessments [2]flow.DDoSAssessment
	for index, match := range matches {
		assessments[index], err = assessMatchedDDoS(ctx, capture, settings, match, benchmarkDDoSWork)
		if err != nil {
			return benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage)}, 0, err
		}
	}
	week := int(end.Sub(assessments[1].Before.To) / (7 * 24 * time.Hour))
	if week < 1 || week > weeks || !assessments[0].Before.To.Equal(assessments[1].Before.From) {
		return benchmarkDDoSOutcome{}, 0, fmt.Errorf("the pair did not retain adjacent original reference windows")
	}
	binding := alert.QueryGroupBinding{TenantID: benchmarkDDoSTenant, RuleID: benchmarkDDoSRule, ViewID: benchmarkDDoSView,
		ViewVersion: input.Version, Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
	episode, _, err := alert.EvaluateDDoSEpisode(ctx, binding, alert.QueryGroupState{}, assessments[0], assessments[1],
		alert.QueryGroupBudget{MemoryBytes: benchmarkDDoSWork, WorkUnits: benchmarkDDoSWork})
	outcome := benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage),
		DemandProven: assessments[0].Application != nil && assessments[0].Application.State == anomaly.DDoSApplicationDemand &&
			assessments[1].Application != nil && assessments[1].Application.State == anomaly.DDoSApplicationDemand}
	if episode != nil {
		outcome.Class = assessments[1].Detection.Class
	}
	return outcome, week, err
}
