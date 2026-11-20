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
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	benchmarkDDoSTenant = "25ebf92b-c387-451d-9e67-0b323c402a58"
	benchmarkDDoSView   = "548baa36-4c4a-47a1-b7d8-7c7f48d36716"
	benchmarkDDoSRule   = "18df565b-2523-443a-b139-eab57d6c0f79"
	benchmarkDDoSWork   = 1 << 20
)

var benchmarkDDoSEpoch = time.Date(2026, 1, 12, 12, 0, 0, 0, time.UTC)

// Every field describes an offline flow aggregate. No socket, raw packet,
// payload, endpoint operation, or delivery schedule is present in this fixture.
type benchmarkDDoSWindow struct {
	Profile                      string
	Bytes, Packets               int
	Records, Addresses, Sampling int
	Complete                     bool
}

type benchmarkDDoSTrial struct {
	Name    string
	Windows [2]benchmarkDDoSWindow
}

func benchmarkDDoSFixture() (flow.DDoSAssessmentInput, benchmarkDDoSWindow, []benchmarkDDoSTrial) {
	input := flow.DDoSAssessmentInput{
		Version: "7", Prefix: "192.0.2.0/24", Direction: "ingress", PeriodSeconds: 60,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 50, MinObservedAddresses: 8,
	}
	reference := benchmarkDDoSWindow{"ordinary", 100000, 1000, 64, 1, 1, true}
	volume := benchmarkDDoSWindow{"ordinary", 400000, 4000, 64, 1, 1, true}
	syn := benchmarkDDoSWindow{"syn", 400000, 4000, 64, 1, 1, true}
	service := benchmarkDDoSWindow{"service", 400000, 4000, 64, 1, 1, true}
	spread := benchmarkDDoSWindow{"ordinary", 400000, 4000, 64, 16, 1, true}
	sampled := benchmarkDDoSWindow{"ordinary", 400000, 4000, 64, 1, 20, true}
	mild := benchmarkDDoSWindow{"ordinary", 170000, 1700, 64, 1, 1, true}
	few := benchmarkDDoSWindow{"ordinary", 400000, 4000, 16, 1, 1, true}
	missingPositive, missingNegative := volume, reference
	missingPositive.Complete, missingNegative.Complete = false, false
	return input, reference, []benchmarkDDoSTrial{
		{"volume", [2]benchmarkDDoSWindow{volume, volume}},
		{"tcp_flags", [2]benchmarkDDoSWindow{syn, syn}},
		{"udp_service", [2]benchmarkDDoSWindow{service, service}},
		{"destination_spread", [2]benchmarkDDoSWindow{spread, spread}},
		{"sampled_volume", [2]benchmarkDDoSWindow{sampled, sampled}},
		{"low_intensity", [2]benchmarkDDoSWindow{mild, mild}},
		{"flash_crowd", [2]benchmarkDDoSWindow{volume, volume}},
		{"stable", [2]benchmarkDDoSWindow{reference, reference}},
		{"single_window", [2]benchmarkDDoSWindow{volume, reference}},
		{"below_observation_floor", [2]benchmarkDDoSWindow{few, few}},
		{"changing_vector", [2]benchmarkDDoSWindow{syn, service}},
		{"partial_positive", [2]benchmarkDDoSWindow{volume, missingPositive}},
		{"partial_negative", [2]benchmarkDDoSWindow{missingNegative, reference}},
	}
}

// This oracle is independent of the records and never enters the assessment.
func benchmarkDDoSLabels() map[string]bool {
	return map[string]bool{
		"volume": true, "tcp_flags": true, "udp_service": true,
		"destination_spread": true, "sampled_volume": true, "low_intensity": true, "partial_positive": true,
		"flash_crowd": false, "stable": false, "single_window": false, "below_observation_floor": false,
		"changing_vector": false, "partial_negative": false,
	}
}

func benchmarkDDoSRows(window benchmarkDDoSWindow) []flowstore.PlanRow {
	rows := make([]flowstore.PlanRow, 0, window.Addresses)
	for index := range window.Addresses {
		address := netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)})
		group := map[string]string{"dst_addr": address.String(), "sampling": strconv.Itoa(window.Sampling),
			"transport": "tcp", "tcp_flags": "16"}
		switch window.Profile {
		case "syn":
			group["tcp_flags"] = "2"
		case "service":
			group["transport"], group["src_port"] = "udp", "53"
		}
		rows = append(rows, flowstore.PlanRow{Group: group, Metrics: map[string]string{
			"bytes:total":   strconv.Itoa(benchmarkDDoSShare(window.Bytes, window.Addresses, index)),
			"packets:total": strconv.Itoa(benchmarkDDoSShare(window.Packets, window.Addresses, index)),
			"flows:total":   strconv.Itoa(benchmarkDDoSShare(window.Records, window.Addresses, index)),
		}})
	}
	return rows
}

func benchmarkDDoSShare(total, groups, index int) int {
	portion := total / groups
	if index < total%groups {
		portion++
	}
	return portion
}

func benchmarkDDoSProjection(ctx context.Context, settings ddosAssessmentSettings, window benchmarkDDoSWindow, from, to time.Time) (anomaly.DDoSObservation, flow.DDoSWindowEvidence, error) {
	return projectDDoSWindow(ctx, capturedReportFlow{
		ID: settings.View.ID, Version: settings.View.Version, TenantID: benchmarkDDoSTenant,
		Result: flowstore.PlanResult{
			OldestInput: from, Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: window.Complete},
			Query: flow.QueryPlan{View: "table", From: from, To: to}, Source: "raw", ResolutionSeconds: 1,
			Rows: benchmarkDDoSRows(window),
		},
	}, settings, "synthetic-fixture-v1", benchmarkDDoSWork)
}

func benchmarkDDoSAssess(ctx context.Context, settings ddosAssessmentSettings, reference, current benchmarkDDoSWindow, clocks anomaly.FlowFieldComparisonClocks) (flow.DDoSAssessment, error) {
	before, beforeEvidence, err := benchmarkDDoSProjection(ctx, settings, reference, clocks.Before.Start, clocks.Before.End)
	if err != nil {
		return flow.DDoSAssessment{}, err
	}
	after, afterEvidence, err := benchmarkDDoSProjection(ctx, settings, current, clocks.After.Start, clocks.After.End)
	if err != nil {
		return flow.DDoSAssessment{}, err
	}
	detection, err := anomaly.EvaluateDDoS(ctx, before, after, settings.Input.Thresholds(), benchmarkDDoSWork)
	return flow.DDoSAssessment{
		ViewID: settings.View.ID, Version: settings.View.Version, Prefix: settings.Target.String(), Direction: settings.Input.Direction,
		Before: beforeEvidence, After: afterEvidence, Detection: detection,
	}, err
}

type benchmarkDDoSOutcome struct {
	Class        anomaly.DDoSClass
	Service      string
	DelaySeconds int
	Abstained    bool
}

func benchmarkDDoSEvaluate(ctx context.Context, input flow.DDoSAssessmentInput, reference benchmarkDDoSWindow, trial benchmarkDDoSTrial) (benchmarkDDoSOutcome, error) {
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, input)
	if err != nil {
		return benchmarkDDoSOutcome{}, err
	}
	end := benchmarkDDoSEpoch.Add(2 * time.Duration(input.PeriodSeconds) * time.Second)
	clocks, err := ddosClocks(end, input.PeriodSeconds)
	if err != nil {
		return benchmarkDDoSOutcome{}, err
	}
	previous, err := benchmarkDDoSAssess(ctx, settings, reference, trial.Windows[0], clocks.Previous)
	if err != nil {
		return benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage)}, err
	}
	current, err := benchmarkDDoSAssess(ctx, settings, reference, trial.Windows[1], clocks.Current)
	if err != nil {
		return benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage)}, err
	}
	binding := alert.QueryGroupBinding{TenantID: benchmarkDDoSTenant, RuleID: benchmarkDDoSRule, ViewID: settings.View.ID,
		ViewVersion: input.Version, Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
	episode, _, err := alert.EvaluateDDoSEpisode(ctx, binding, alert.QueryGroupState{}, previous, current,
		alert.QueryGroupBudget{MemoryBytes: benchmarkDDoSWork, WorkUnits: benchmarkDDoSWork})
	if err != nil || episode == nil {
		return benchmarkDDoSOutcome{}, err
	}
	return benchmarkDDoSOutcome{Class: current.Detection.Class, Service: current.Detection.Service,
		DelaySeconds: int(current.After.To.Sub(benchmarkDDoSEpoch).Seconds())}, nil
}

type benchmarkDDoSCounts struct {
	TruePositive, FalsePositive, TrueNegative, FalseNegative int
	AbstainedPositive, AbstainedNegative                     int
}

func (counts *benchmarkDDoSCounts) record(positive bool, outcome benchmarkDDoSOutcome) {
	switch {
	case outcome.Abstained && positive:
		counts.AbstainedPositive++
	case outcome.Abstained:
		counts.AbstainedNegative++
	case outcome.Class != "" && positive:
		counts.TruePositive++
	case outcome.Class != "":
		counts.FalsePositive++
	case positive:
		counts.FalseNegative++
	default:
		counts.TrueNegative++
	}
}

func TestSyntheticDDoSDetectionBenchmark(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	input, reference, trials := benchmarkDDoSFixture()
	labels := benchmarkDDoSLabels()
	if len(labels) != len(trials) {
		t.Fatal("fixture and label oracle have different case counts")
	}
	manifest, err := json.Marshal(struct {
		Epoch     time.Time
		Settings  flow.DDoSAssessmentInput
		Reference benchmarkDDoSWindow
		Trials    []benchmarkDDoSTrial
		Labels    map[string]bool
	}{benchmarkDDoSEpoch, input, reference, trials, labels})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture_manifest_sha256=%s", hex.EncodeToString(crypto.Hash(manifest)))
	rows := [][]flowstore.PlanRow{benchmarkDDoSRows(reference)}
	for _, trial := range trials {
		for _, window := range trial.Windows {
			rows = append(rows, benchmarkDDoSRows(window))
		}
	}
	encodedRows, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture_rows_sha256=%s", hex.EncodeToString(crypto.Hash(encodedRows)))
	wantedClasses := map[string]anomaly.DDoSClass{
		"volume": anomaly.DDoSVolumetric, "tcp_flags": anomaly.DDoSSYN, "udp_service": anomaly.DDoSReflection,
		"destination_spread": anomaly.DDoSPrefixSpread, "sampled_volume": anomaly.DDoSVolumetric, "flash_crowd": anomaly.DDoSVolumetric,
	}
	var counts benchmarkDDoSCounts
	for _, trial := range trials {
		positive, labeled := labels[trial.Name]
		if !labeled {
			t.Fatalf("fixture %q has no independent label", trial.Name)
		}
		outcome, err := benchmarkDDoSEvaluate(ctx, input, reference, trial)
		if err != nil && !outcome.Abstained {
			t.Fatalf("assessment %q: %v", trial.Name, err)
		}
		if outcome.Class != wantedClasses[trial.Name] {
			t.Errorf("trial %q classified as %q, want %q", trial.Name, outcome.Class, wantedClasses[trial.Name])
		}
		if outcome.Class != "" && outcome.DelaySeconds != 2*input.PeriodSeconds {
			t.Errorf("trial %q episode delay %ds", trial.Name, outcome.DelaySeconds)
		}
		if trial.Name == "udp_service" && outcome.Service != "dns" {
			t.Errorf("trial %q observed service %q", trial.Name, outcome.Service)
		}
		t.Logf("case=%s label_positive=%t class=%q service=%q abstained=%t episode_delay_seconds=%d",
			trial.Name, positive, outcome.Class, outcome.Service, outcome.Abstained, outcome.DelaySeconds)
		counts.record(positive, outcome)
	}
	t.Logf("true_positive=%d false_positive=%d true_negative=%d false_negative=%d abstained_positive=%d abstained_negative=%d",
		counts.TruePositive, counts.FalsePositive, counts.TrueNegative, counts.FalseNegative, counts.AbstainedPositive, counts.AbstainedNegative)
	want := benchmarkDDoSCounts{TruePositive: 5, FalsePositive: 1, TrueNegative: 4, FalseNegative: 1, AbstainedPositive: 1, AbstainedNegative: 1}
	if counts != want {
		t.Errorf("confusion matrix %+v, want %+v", counts, want)
	}
}

func BenchmarkSyntheticDDoSDetection(b *testing.B) {
	ctx := tenancy.WithTenant(b.Context(), tenancy.ID(benchmarkDDoSTenant))
	input, reference, trials := benchmarkDDoSFixture()
	b.ReportAllocs()
	for b.Loop() {
		for _, trial := range trials {
			outcome, err := benchmarkDDoSEvaluate(ctx, input, reference, trial)
			if err != nil && !outcome.Abstained {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(len(trials)), "cases/op")
}
