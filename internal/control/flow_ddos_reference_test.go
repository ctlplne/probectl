// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCitedDDoSClockKeepsSelectedWeekForBothEvidenceWindows(t *testing.T) {
	end := time.Date(2026, time.November, 20, 14, 15, 5, 0, time.UTC)
	settings := ddosAssessmentSettings{Input: flow.DDoSAssessmentInput{PeriodSeconds: 5, ReferenceMode: flow.DDoSReferenceWeeklyRepresentative}}
	clock, err := ddosClocks(end, settings.Input.PeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	fill := func(w anomaly.FlowFieldComparisonClocks, week int) flow.DDoSAssessment {
		return flow.DDoSAssessment{ReferenceMode: settings.Input.ReferenceMode,
			Before: flow.DDoSWindowEvidence{From: w.After.Start.AddDate(0, 0, -7*week), To: w.After.End.AddDate(0, 0, -7*week)},
			After:  flow.DDoSWindowEvidence{From: w.After.Start, To: w.After.End}}
	}
	proof := alert.DDoSEvaluationEvidence{Previous: fill(clock.Previous, 3), Current: fill(clock.Current, 3)}
	kept, err := citedDDoSClocks(proof, settings)
	if err != nil || !kept.Previous.Before.End.Equal(proof.Previous.Before.To) || !kept.Current.Before.End.Equal(proof.Current.Before.To) {
		t.Fatal("routing review did not keep both original reference clocks", kept, err)
	}
	proof.Previous = fill(clock.Previous, 2)
	if _, err := citedDDoSClocks(proof, settings); !errors.Is(err, alert.ErrQueryGroups) {
		t.Fatal("a mixed-week episode could be reconstructed as an original", err)
	}
	settings.Input.ReferenceMode = ""
	proof = alert.DDoSEvaluationEvidence{Previous: fill(clock.Previous, 3), Current: fill(clock.Current, 3)}
	if _, err := citedDDoSClocks(proof, settings); !errors.Is(err, alert.ErrQueryGroups) {
		t.Fatal("legacy rules could use an unexpected reference week", err)
	}
}

func TestDDoSWeeklyReferenceRequiresExporterCoverage(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	const period = 5
	end := time.Date(2026, time.November, 20, 14, 15, 5, 0, time.UTC)
	exporters := []string{"203.0.113.16", "203.0.113.15"}
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, flow.DDoSAssessmentInput{
		Version: "1", Prefix: "192.0.2.0/24", Direction: "ingress", PeriodSeconds: period,
		ReferenceMode: flow.DDoSReferenceWeeklyRepresentative, RequiredExporters: exporters,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
		VectorShareBasisPoints: 6000, MinObservedRecords: 2, MinObservedAddresses: 2,
	})
	if err != nil || exporters[0] != "203.0.113.16" || settings.Input.RequiredExporters[0] != "203.0.113.15" {
		t.Fatal("could not freeze the configured exporter set without modifying caller input", err)
	}
	clocks, err := ddosClocks(end, period)
	if err != nil {
		t.Fatal(err)
	}
	capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1}
	for _, windowEnd := range ddosReferenceEnds(4, clocks.Previous, clocks.Current) {
		from := windowEnd.Add(-period * time.Second)
		rows := benchmarkDDoSRows(benchmarkDDoSWindow{Bytes: 360000, Packets: 3600, Records: 20, Addresses: 2, Sampling: 1})
		for i, exporter := range exporters {
			rows[i].Group["exporter"] = exporter
		}
		capture.Results = append(capture.Results, capturedReportFlow{
			TenantID: benchmarkDDoSTenant, ID: settings.View.ID, Version: settings.View.Version,
			Result: flowstore.PlanResult{OldestInput: from, Source: "raw", ResolutionSeconds: 1,
				Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true},
				Query:    flow.QueryPlan{View: "table", From: from, To: windowEnd}, Rows: rows},
		})
	}
	latest := len(capture.Results) - 1
	// The most recent weekly pair is missing one exporter from one window.
	capture.Results[latest-2].Result.Rows = capture.Results[latest-2].Result.Rows[:1]
	selected, err := ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current)
	if err != nil || len(selected) != 2 || !selected[1].clocks.Before.End.Equal(end.AddDate(0, 0, -14)) ||
		!selected[0].clocks.Before.End.Equal(end.Add(-period*time.Second).AddDate(0, 0, -14)) {
		t.Fatal("the reference did not select both windows of the latest complete historical pair", selected, err)
	}
	complete := capture.Results[latest-4].Result.Rows
	capture.Results[latest-4].Result.Rows = complete[:1]
	if _, err := ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current); !errors.Is(err, anomaly.ErrDDoSCoverage) {
		t.Fatal("two complete historical weeks were accepted as a representative reference", err)
	}
	capture.Results[latest-4].Result.Rows = complete

	// Restore the most recent week, but give only its second window a
	// different reported rate at one of the original exporters.
	recent := capture.Results[latest-2].Result.Rows
	capture.Results[latest-2].Result.Rows = recent[:2]
	capture.Results[latest-2].Result.Rows[1].Group["sampling"] = "8"
	selected, err = ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current)
	if err != nil || len(selected) != 2 || !selected[1].clocks.Before.End.Equal(end.AddDate(0, 0, -14)) {
		t.Fatal("a week with an incomparable exporter rate entered the representative pair", selected, err)
	}
	capture.Results[latest-4].Result.Rows[1].Group["sampling"] = "8"
	if _, err := ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current); !errors.Is(err, anomaly.ErrDDoSCoverage) {
		t.Fatal("two sampling-comparable weeks were accepted as a representative reference", err)
	}
	capture.Results[latest-4].Result.Rows[1].Group["sampling"] = "1"
	current := capture.Results[latest].Result.Rows
	capture.Results[latest].Result.Rows = current[:1]
	if _, err := ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current); !errors.Is(err, errDDoSExporterCoverage) {
		t.Fatal("the latest partial observation was accepted", err)
	}
	capture.Results[latest].Result.Rows = current
	capture.Results[latest-2].Result.Rows = capture.Results[latest-2].Result.Rows[:2]
	settings.Input.MinObservedRecords = 4
	for _, result := range capture.Results {
		for _, row := range result.Result.Rows {
			row.Group["sampling"] = "8"
		}
	}
	capture.Results[latest-2].Result.Rows[0].Metrics["flows:total"] = "1"
	selected, err = ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current)
	if err != nil || len(selected) != 2 || !selected[1].clocks.Before.End.Equal(end.AddDate(0, 0, -14)) {
		t.Fatal("a sparsely sampled window entered the representative week", selected, err)
	}
	current[0].Metrics["flows:total"] = "1"
	if _, err := ddosMatchedWindows(ctx, capture, settings, benchmarkDDoSWork, clocks.Previous, clocks.Current); !errors.Is(err, errDDoSSampleCoverage) {
		t.Fatal("the sparse current observation became usable coverage", err)
	}
}

func TestDDoSWeeklyTrendRequiresFourComparableOriginalWeeks(t *testing.T) {
	end := time.Date(2026, time.November, 20, 14, 15, 5, 0, time.UTC)
	const minimum = 20
	counts := [5]int{3400, 3680, 3960, 4640, 5200}
	build := func() []anomaly.DDoSObservation {
		observations := make([]anomaly.DDoSObservation, len(counts))
		for i, packets := range counts {
			observations[i] = anomaly.DDoSObservation{
				To: end.AddDate(0, 0, -7*(4-i)), Complete: true, ObservedRecords: minimum,
				Packets: strconv.Itoa(packets), Bytes: strconv.Itoa(100 * packets),
			}
		}
		return observations
	}
	for _, candidate := range []struct {
		name   string
		update func([]anomaly.DDoSObservation)
		want   bool
	}{
		{name: "same-clock observed growth", update: func([]anomaly.DDoSObservation) {}, want: true},
		{name: "missing original window", update: func(o []anomaly.DDoSObservation) { o[1].Complete = false }},
		{name: "insufficient source rows", update: func(o []anomaly.DDoSObservation) { o[1].ObservedRecords = minimum - 1 }},
		{name: "different historical clock", update: func(o []anomaly.DDoSObservation) { o[1].To = o[1].To.Add(-time.Second) }},
		{name: "byte growth faster than history", update: func(o []anomaly.DDoSObservation) { o[4].Bytes = "660000" }},
		{name: "packet growth faster than history", update: func(o []anomaly.DDoSObservation) { o[4].Packets = "6600" }},
		{name: "the prior week did not grow", update: func(o []anomaly.DDoSObservation) { o[3].Packets = o[2].Packets }},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			observations := build()
			candidate.update(observations)
			if got := followsDDoSWeeklyTrend(observations, 1, 0, minimum); got != candidate.want {
				t.Fatalf("trend comparison: got %t, want %t", got, candidate.want)
			}
		})
	}
}
