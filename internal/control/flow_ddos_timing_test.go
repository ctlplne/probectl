// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDDoSTimingRechecksCrossPlaneDemand(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: 5,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 50, MinObservedAddresses: 2, Application: &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}}
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, input)
	if err != nil {
		t.Fatal(err)
	}
	clocks, err := anomaly.DDoSCompletedWindows(benchmarkDDoSEpoch, input.PeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	reference := benchmarkDDoSWindow{Bytes: 220000, Packets: 2200, Records: 64, Addresses: 1, Sampling: 1}
	current := reference
	current.Bytes, current.Packets = 440000, 4400
	current.OtherBytes, current.OtherPackets = 300000, 3000
	settings.readApplication = func(ctx context.Context, observation anomaly.DDoSObservation) (anomaly.DDoSApplicationWindow, bool, error) {
		app := benchmarkDDoSApplication{Requests: 40, LatencyMS: 20}
		if observation.From.Equal(clocks.After.Start) {
			app.Requests = 80
		}
		spans := benchmarkDDoSAppSpans(app, observation.From)
		return projectDDoSApplicationWindow(ctx, observation, input.Application.Service, input.Application.Port, observation.To, spans)
	}
	capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1,
		Results: []capturedReportFlow{fixtureDDoSTimingWindow(settings, clocks.Before, reference), fixtureDDoSTimingWindow(settings, clocks.After, current)}}
	whole, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
	if err != nil || whole.Detection == nil || whole.Application == nil || whole.Application.State != anomaly.DDoSApplicationResidual {
		t.Fatal("the original independent pressure condition should be measurable before checking timing", whole, err)
	}
	// Only the extra listener's original interval crosses the boundary. On
	// its own, the remaining listener increase is healthy app demand.
	capture.Results[1].Result.Rows[1].CrossesWindowStart = true
	if got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork); !errors.Is(err, errDDoSTimingCoverage) || got.Detection != nil {
		t.Fatal("the crossing reports turned contemporaneous healthy demand into a confirmed finding", got, err)
	}
	settings.Cited = true
	// An incident report or routing review replays the saved scope and
	// figures. A decision from before timing admission remains readable.
	replayed, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
	if err != nil || !sameDDoSRoutingEvidence(whole, replayed) {
		t.Fatal("a new timing admission rule invalidated the existing receipt", replayed, err)
	}
}

func TestDDoSTimingCannotEstablishQuietFromCrossingReportsAlone(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	for _, seconds := range []int{5, 10, 60} {
		settings, err := normalizeDDoSAssessment(benchmarkDDoSView, flow.DDoSAssessmentInput{
			Version: "7", Prefix: "192.0.2.0/24", Direction: "ingress", PeriodSeconds: seconds,
			BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 4, MinObservedAddresses: 2,
		})
		if err != nil {
			t.Fatal(err)
		}
		clocks, err := anomaly.DDoSCompletedWindows(benchmarkDDoSEpoch, seconds)
		if err != nil {
			t.Fatal(err)
		}
		quiet := benchmarkDDoSWindow{Bytes: 320000, Packets: 3200, Records: 8, Addresses: 2, Sampling: 1}
		capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1,
			Results: []capturedReportFlow{fixtureDDoSTimingWindow(settings, clocks.Before, quiet), fixtureDDoSTimingWindow(settings, clocks.After, quiet)}}
		rows := capture.Results[1].Result.Rows
		for i := range rows {
			rows[i].CrossesWindowStart = true
		}
		got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
		if anomaly.DDoSFastPeriod(seconds) {
			if !errors.Is(err, errDDoSTimingCoverage) {
				t.Fatal("crossing reports alone established short-window quiet", seconds, got, err)
			}
		} else if err != nil || got.Detection != nil {
			t.Fatal("the longer cadence lost its quiet observation", seconds, got, err)
		}
		rows[0].CrossesWindowStart = false
		if got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork); err != nil || got.Detection != nil {
			t.Fatal("contained observations did not support quiet", seconds, got, err)
		}
		rows[0].Metrics["flows:total"] = "1"
		got, err = assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
		if anomaly.DDoSFastPeriod(seconds) {
			if !errors.Is(err, errDDoSTimingCoverage) {
				t.Fatal("one contained unsampled record established short-window quiet", seconds, got, err)
			}
		} else if err != nil || got.Detection != nil {
			t.Fatal("the longer cadence lost its quiet observation", seconds, got, err)
		}
	}
}

func TestDDoSTimingRequiresQuietInContainedReports(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	for _, period := range []int{5, 10, 60} {
		settings, err := normalizeDDoSAssessment(benchmarkDDoSView, flow.DDoSAssessmentInput{
			Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: period,
			BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 4, MinObservedAddresses: 2,
		})
		if err != nil {
			t.Fatal(err)
		}
		clocks, err := anomaly.DDoSCompletedWindows(benchmarkDDoSEpoch, period)
		if err != nil {
			t.Fatal(err)
		}
		reference := benchmarkDDoSWindow{Bytes: 640000, Packets: 6400, Records: 8, Addresses: 1, Sampling: 1}
		for _, profile := range []string{"syn", "dns"} {
			current := benchmarkDDoSWindow{Bytes: 320000, Packets: 3200, Records: 4, Addresses: 1, Sampling: 1,
				Profile: profile, OtherBytes: 320000, OtherPackets: 3200}
			capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1,
				Results: []capturedReportFlow{fixtureDDoSTimingWindow(settings, clocks.Before, reference), fixtureDDoSTimingWindow(settings, clocks.After, current)}}
			got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
			if err != nil || got.Detection != nil {
				t.Fatal("a contained vector below the share threshold should be quiet", period, profile, got, err)
			}
			capture.Results[1].Result.Rows[1].CrossesWindowStart = true
			got, err = assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
			if anomaly.DDoSFastPeriod(period) {
				if !errors.Is(err, errDDoSTimingCoverage) || got.Detection != nil {
					t.Fatal("a vector supported by contained reports was interpreted as quiet", period, profile, got, err)
				}
			} else if err != nil || got.Detection != nil {
				t.Fatal("the longer cadence lost its quiet observation", period, profile, got, err)
			}
		}
	}
}

func TestDDoSTimingRequiresComparableSamplingAfterRemovingCrossingReports(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	const exporter = "203.0.113.15"
	input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: 5,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 50, MinObservedAddresses: 2, RequiredExporters: []string{exporter}}
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, input)
	if err != nil {
		t.Fatal(err)
	}
	clocks, err := anomaly.DDoSCompletedWindows(benchmarkDDoSEpoch, input.PeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	reference := benchmarkDDoSWindow{Bytes: 140000, Packets: 1700, Records: 64, Addresses: 1, Sampling: 1,
		OtherBytes: 80000, OtherPackets: 800}
	current := reference
	current.Bytes, current.Packets = 360000, 3600
	capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1,
		Results: []capturedReportFlow{fixtureDDoSTimingWindow(settings, clocks.Before, reference), fixtureDDoSTimingWindow(settings, clocks.After, current)}}
	for _, result := range capture.Results {
		for _, row := range result.Result.Rows {
			row.Group["exporter"] = exporter
		}
		result.Result.Rows[1].Group["sampling"] = "8"
		result.Result.Rows[1].Metrics["flows:total"] = "50"
	}
	got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
	if err != nil || got.Detection == nil || got.Detection.Class != anomaly.DDoSVolumetric {
		t.Fatal("pressure should be measurable with both original sampling rates", got, err)
	}
	capture.Results[1].Result.Rows[1].CrossesWindowStart = true
	got, err = assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
	if !errors.Is(err, errDDoSTimingCoverage) || got.Detection != nil {
		t.Fatal("removing a crossing interval made a changed sampling profile look comparable", got, err)
	}
	// Repeat with steady totals. The unsampled row still fits the current
	// window, but only a crossing interval supports the second rate.
	capture.Results[1] = fixtureDDoSTimingWindow(settings, clocks.After, reference)
	for _, row := range capture.Results[1].Result.Rows {
		row.Group["exporter"] = exporter
	}
	sampled := &capture.Results[1].Result.Rows[1]
	sampled.Group["sampling"] = "8"
	sampled.Metrics["flows:total"] = "50"
	if got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork); err != nil || got.Detection != nil {
		t.Fatal("steady traffic from both rates should establish quiet coverage", got, err)
	}
	sampled.CrossesWindowStart = true
	if got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork); !errors.Is(err, errDDoSTimingCoverage) {
		t.Fatal("a contained row at a different rate established quiet coverage", got, err)
	}
}

func TestDDoSSampledEvidenceRequiresOwnOriginalRecords(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, flow.DDoSAssessmentInput{
		Version: "7", Prefix: "192.0.2.0/24", Direction: "ingress", PeriodSeconds: 5,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 4, MinObservedAddresses: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	clocks, err := anomaly.DDoSCompletedWindows(benchmarkDDoSEpoch, settings.Input.PeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	window := fixtureDDoSTimingWindow(settings, clocks.After, benchmarkDDoSWindow{
		Bytes: 320000, Packets: 3200, Records: 8, Addresses: 2, Sampling: 8,
	})
	rows := window.Result.Rows
	rows[1].Metrics["flows:total"] = "1"
	for _, otherRate := range []string{"1", "4"} {
		rows[0].Group["sampling"] = otherRate
		if _, err := projectDDoSWindow(ctx, window, settings, "scope", benchmarkDDoSWork); !errors.Is(err, errDDoSSampleCoverage) {
			t.Fatal("another sampling rate supplied the missing originals", otherRate, err)
		}
	}
	rows[0].Group["sampling"] = "8"
	if got, err := projectDDoSWindow(ctx, window, settings, "scope", benchmarkDDoSWork); err != nil || got.evidence.ObservedRecords != 5 {
		t.Fatal("originals within the same rate failed to support the observation", got.evidence, err)
	}
}

func fixtureDDoSTimingWindow(settings ddosAssessmentSettings, clock anomaly.TrainingWindow, window benchmarkDDoSWindow) capturedReportFlow {
	return capturedReportFlow{ID: settings.View.ID, Version: settings.View.Version, TenantID: benchmarkDDoSTenant,
		Result: flowstore.PlanResult{OldestInput: clock.Start, Source: "raw", ResolutionSeconds: 1,
			Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true},
			Query:    flow.QueryPlan{View: "table", From: clock.Start, To: clock.End}, Rows: benchmarkDDoSRows(window)}}
}

func TestDDoSDeclinesInvalidSamplingCounters(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: 5,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 50, MinObservedAddresses: 2}
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, input)
	if err != nil {
		t.Fatal(err)
	}
	clocks, err := anomaly.DDoSCompletedWindows(benchmarkDDoSEpoch, input.PeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	reference := benchmarkDDoSWindow{Bytes: 90000, Packets: 900, Records: 64, Addresses: 1, Sampling: 2}
	current := reference
	current.Bytes, current.Packets = 360000, 3600
	capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1,
		Results: []capturedReportFlow{fixtureDDoSTimingWindow(settings, clocks.Before, reference), fixtureDDoSTimingWindow(settings, clocks.After, current)}}
	row := &capture.Results[1].Result.Rows[0]
	row.InvalidSamplingCounters = true
	got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
	if !errors.Is(err, errDDoSCounterIntegrity) || got.Detection != nil {
		t.Fatal("inconsistent corrected counters supported a new assessment", got, err)
	}
	settings.Cited = true
	got, err = assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
	if err != nil || got.Detection == nil || got.After.Packets != "3600" {
		t.Fatal("an original receipt can no longer be reconstructed from the stored counters", got, err)
	}
}
