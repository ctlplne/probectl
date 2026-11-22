// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSyntheticFastDDoSFindsOutsideApplicationPressureWithFlatHostTotals(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	reference := benchmarkDDoSWindow{Bytes: 320000, Packets: 3200, OtherBytes: 80000, OtherPackets: 800, Records: 64,
		Addresses: 1, Sampling: 1, Complete: true, Application: benchmarkDDoSApplication{Requests: 80, LatencyMS: 25}}
	outside := reference
	outside.Bytes, outside.Packets, outside.OtherBytes, outside.OtherPackets = 120000, 1200, 280000, 2800
	outside.Application.Requests = 30
	missingApp := outside
	missingApp.Application.Requests = 0
	for _, period := range []int{5, 10, 60} {
		settings := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: period,
			BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
			MinObservedRecords: 50, MinObservedAddresses: 2, Application: &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}}
		for _, sample := range []struct {
			name    string
			current benchmarkDDoSWindow
			want    benchmarkDDoSOutcome
		}{
			{"unchanged split", reference, benchmarkDDoSOutcome{}},
			{"independent outside pressure", outside, benchmarkDDoSOutcome{Class: anomaly.DDoSVolumetric, Residual: true, DelaySeconds: period * 2}},
			{"outside pressure without application evidence", missingApp, benchmarkDDoSOutcome{Abstained: true}},
		} {
			if !anomaly.DDoSFastPeriod(period) {
				sample.want = benchmarkDDoSOutcome{}
			}
			got, err := benchmarkDDoSEvaluate(ctx, benchmarkDDoSTrial{Settings: settings, Reference: reference,
				Windows: [2]benchmarkDDoSWindow{sample.current, sample.current}})
			if got != sample.want || (err != nil && !sample.want.Abstained) || (sample.want.Abstained && !errors.Is(err, anomaly.ErrDDoSCoverage)) {
				t.Fatal("unexpected flat-host result", period, sample.name, got, sample.want, err)
			}
		}
	}
}

func TestFastDDoSOutsideTrafficRequiresSocketAttribution(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, flow.DDoSAssessmentInput{
		Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: 5,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 50, MinObservedAddresses: 2, Application: &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	clocks, err := anomaly.DDoSCompletedWindows(benchmarkDDoSEpoch, 5)
	if err != nil {
		t.Fatal(err)
	}
	reference := benchmarkDDoSWindow{Bytes: 320000, Packets: 3200, OtherBytes: 80000, OtherPackets: 800,
		Records: 64, Addresses: 1, Sampling: 1, Complete: true}
	current := reference
	current.Bytes, current.Packets, current.OtherBytes, current.OtherPackets = 120000, 1200, 280000, 2800
	for _, sample := range []struct {
		transport, port string
		outside         bool
	}{
		{"", "443", false}, {"0", "443", false}, {"0", "8443", true}, {"udp", "443", true},
	} {
		later := benchmarkDDoSCapturedWindow(settings, current, clocks.After.Start, clocks.After.End)
		group := later.Result.Rows[1].Group
		group["transport"], group["dst_port"], group["src_port"] = sample.transport, sample.port, "40000"
		capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1, Results: []capturedReportFlow{
			benchmarkDDoSCapturedWindow(settings, reference, clocks.Before.Start, clocks.Before.End), later,
		}}
		got, err := assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
		if sample.outside {
			if err != nil || got.Detection == nil || got.Detection.Class != anomaly.DDoSVolumetric {
				t.Fatal("independently attributed outside traffic did not qualify", sample, got, err)
			}
		} else if !errors.Is(err, anomaly.ErrDDoSCoverage) || got.Detection != nil {
			t.Fatal("a missing transport field counted as known socket evidence", sample, got, err)
		}
	}
}

func TestDDoSApplicationKeepsCompletedRequestsThatCrossTheWindowEnd(t *testing.T) {
	from := time.Date(2026, time.November, 20, 11, 30, 0, 0, time.UTC)
	to := from.Add(5 * time.Second)
	window := anomaly.DDoSObservation{TenantID: benchmarkDDoSTenant, Target: netip.MustParsePrefix("192.0.2.1/32"), From: from, To: to}
	spans := benchmarkDDoSAppSpans(benchmarkDDoSApplication{Requests: 20, LatencyMS: 25}, from)
	spans[0].Start = to.Add(-5 * time.Millisecond)
	completion := spans[0].Start.Add(spans[0].Duration)
	observed, usable, err := projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion, spans)
	if err != nil || !usable || observed.Requests != 20 || observed.Successes != 20 || len(observed.Digest) != 64 {
		t.Fatal("a completed request left the matching observation clock unqualified", observed, usable, err)
	}
	if _, usable, err := projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion.Add(-time.Nanosecond), spans); err != nil || usable {
		t.Fatal("future evidence qualified the current observation", err)
	}
	spans[0].Duration = 6 * time.Second
	spans[1].Duration = 6 * time.Second
	completion = spans[0].Start.Add(spans[0].Duration)
	if _, usable, err := projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion.Add(-time.Nanosecond), spans); err != nil || usable {
		t.Fatal("an ongoing slow request qualified the current observation", err)
	}
	observed, usable, err = projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion, spans)
	if err != nil || !usable || observed.Requests != 20 || observed.P95 != 6*time.Second {
		t.Fatal("completed slow requests did not contribute their measured latency", observed, usable, err)
	}
}

func TestFastDDoSAbstainsWhenSamplingConcealsHealthyDemand(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: 5,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 20, MinObservedAddresses: 2,
		Application: &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}}
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, input)
	if err != nil {
		t.Fatal(err)
	}
	clocks, err := ddosClocks(benchmarkDDoSEpoch.Add(10*time.Second), 5)
	if err != nil {
		t.Fatal(err)
	}
	base := benchmarkDDoSWindow{Profile: "ordinary", Bytes: 90000, Packets: 900, Records: 64, Addresses: 1, Sampling: 1, Complete: true}
	crowd := base
	crowd.Bytes, crowd.Packets = base.Bytes*4, base.Packets*4
	assess := func(pair anomaly.FlowFieldComparisonClocks) flow.DDoSAssessment {
		t.Helper()
		before, beforeEvidence, err := benchmarkDDoSProjection(ctx, settings, base, pair.Before.Start, pair.Before.End)
		if err != nil {
			t.Fatal(err)
		}
		after, afterEvidence, err := benchmarkDDoSProjection(ctx, settings, crowd, pair.After.Start, pair.After.End)
		if err != nil {
			t.Fatal(err)
		}
		read := func(ctx context.Context, window anomaly.DDoSObservation) (anomaly.DDoSApplicationWindow, bool, error) {
			expected, threshold := 24, "0"
			if window.From.Equal(after.From) {
				expected, threshold = 96, "c"
			}
			spans := benchmarkDDoSAppSpans(benchmarkDDoSApplication{Requests: expected, LatencyMS: 25}, window.From)
			// The 25% fixture exports one quarter of its original healthy population.
			spans = spans[:24]
			for i := range spans {
				spans[i].SamplingThreshold = threshold
			}
			return projectDDoSApplicationWindow(ctx, window, input.Application.Service, input.Application.Port, window.To, spans)
		}
		finding, err := anomaly.EvaluateDDoS(ctx, before, after, input.Thresholds(), benchmarkDDoSWork)
		if err != nil || finding == nil {
			t.Fatal("the synthetic crowd did not trigger generic flow pressure", err)
		}
		finding, application, err := qualifyProjectedDDoS(ctx, before, after, finding, read, input.Thresholds(), benchmarkDDoSWork)
		if err != nil || application == nil || application.Reference.Successes != 24 || application.Current.Successes != 24 {
			t.Fatal("the sampled observation populations were not comparable by raw count alone", err)
		}
		return flow.DDoSAssessment{ViewID: benchmarkDDoSView, Version: input.Version, Prefix: input.Prefix, Direction: input.Direction,
			Before: beforeEvidence, After: afterEvidence, Detection: finding, Application: application}
	}
	previous, current := assess(clocks.Previous), assess(clocks.Current)
	binding := alert.QueryGroupBinding{TenantID: benchmarkDDoSTenant, RuleID: benchmarkDDoSRule, ViewID: benchmarkDDoSView,
		ViewVersion: input.Version, Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
	episode, _, err := alert.EvaluateDDoSEpisode(ctx, binding, alert.QueryGroupState{}, previous, current,
		alert.QueryGroupBudget{MemoryBytes: benchmarkDDoSWork, WorkUnits: benchmarkDDoSWork})
	if episode != nil || !errors.Is(err, anomaly.ErrDDoSCoverage) || current.Application.State != anomaly.DDoSApplicationSampling {
		t.Fatal("a sampling change admitted a healthy crowd as an attack", current.Application.State, episode != nil, err)
	}
}
