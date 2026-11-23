// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type mixedDDoSReplayCase struct {
	name       string
	reference  []flowstore.PlanRow
	current    [2][]flowstore.PlanRow
	positive   bool
	wantVector anomaly.DDoSClass
}

func TestSyntheticDDoSMixedVectorHoldout(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	var inputs []syntheticDDoSReplayTrial
	var truth []syntheticDDoSTruth
	var expected []anomaly.DDoSClass
	for variation := range benchmarkDDoSVars {
		period := 5 + 5*(variation%2)
		end := benchmarkDDoSEpoch.Add(time.Duration(2*period) * time.Second)
		clocks, err := ddosClocks(end, period)
		if err != nil {
			t.Fatal(err)
		}
		settings := flow.DDoSAssessmentInput{Version: "7", Direction: "ingress", Prefix: "192.0.2.1/32", PeriodSeconds: period,
			BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
			MinObservedRecords: 16, MinObservedAddresses: 2}
		for _, scenario := range mixedDDoSHoldoutCases(variation) {
			id := fmt.Sprintf("trial-%04d", len(inputs)+1)
			start := clocks.Previous.After.Start.Add(-time.Duration(variation%period) * time.Second)
			replay := syntheticDDoSReplayTrial{ID: id, Scope: settings, ModeledStart: start}
			for i, pair := range []anomaly.FlowFieldComparisonClocks{clocks.Previous, clocks.Current} {
				replay.Pairs[i] = syntheticDDoSReplayPair{
					Reference: syntheticDDoSReplayWindow{From: pair.Before.Start, To: pair.Before.End, Complete: true, Flows: scenario.reference},
					Current:   syntheticDDoSReplayWindow{From: pair.After.Start, To: pair.After.End, Complete: true, Flows: scenario.current[i]},
				}
			}
			inputs = append(inputs, replay)
			truth = append(truth, syntheticDDoSTruth{ID: id, Scenario: fmt.Sprintf("%s/%02d", scenario.name, variation), Positive: scenario.positive})
			expected = append(expected, scenario.wantVector)
		}
	}
	digest, err := syntheticDDoSRowsDigest(inputs)
	if err != nil {
		t.Fatal(err)
	}
	payload, replay, err := prepareSyntheticDDoSReplayInputs(inputs, digest)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes benchmarkDDoSCounts
	decisions := make([]syntheticDDoSDecision, 0, len(replay))
	for index, trial := range replay {
		outcome, err := evaluateSyntheticDDoSReplay(ctx, trial)
		if err != nil || outcome.Class != expected[index] || outcome.Abstained {
			t.Fatalf("%s: expected class %q, got %+v, %v", truth[index].Scenario, expected[index], outcome, err)
		}
		if outcome.Class != "" {
			end := trial.Pairs[1].Current.To
			if outcome.DelaySeconds != int(end.Sub(trial.ModeledStart).Seconds()) {
				t.Fatal("episode lost its two-window timing", trial.ID, outcome.DelaySeconds)
			}
		}
		outcomes.record(truth[index].Positive, outcome)
		decisions = append(decisions, syntheticDDoSDecisionFor(trial.ID, outcome))
	}
	if outcomes.TruePositive != 64 || outcomes.FalseNegative != 16 || outcomes.TrueNegative != 48 || outcomes.FalsePositive != 0 {
		t.Fatalf("unexpected holdout outcome counts: %+v", outcomes)
	}
	if output := os.Getenv("PROBECTL_TEST_DDOS_MIXED_CORPUS_DIR"); output != "" {
		if err := writeSyntheticDDoSReplay(output, payload, truth, decisions); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("mixed vector holdout: cases=%d true_positive=%d false_negative=%d true_negative=%d false_positive=%d rows_sha256=%s",
		len(inputs), outcomes.TruePositive, outcomes.FalseNegative, outcomes.TrueNegative, outcomes.FalsePositive, digest)
}

func mixedDDoSHoldoutCases(variation int) []mixedDDoSReplayCase {
	// These are aggregate counters for documentation addresses. Equal totals
	// let the vector comparison qualify independently of overall traffic growth.
	total := 8000 + 160*variation
	component := total * 36 / 100
	ordinary := mixedHoldoutFlow("ordinary", total)
	synAndDNS := mixedHoldoutFlow("syn", component)
	synAndDNS = append(synAndDNS, mixedHoldoutFlow("dns", component)...)
	synAndDNS = append(synAndDNS, mixedHoldoutFlow("ordinary", total-2*component)...)
	dnsAndNTP := mixedHoldoutFlow("dns", component)
	dnsAndNTP = append(dnsAndNTP, mixedHoldoutFlow("ntp", component)...)
	dnsAndNTP = append(dnsAndNTP, mixedHoldoutFlow("ordinary", total-2*component)...)
	steadyDNS := append(mixedHoldoutFlow("dns", component), mixedHoldoutFlow("ordinary", total-component)...)
	unknownTransport := mixedHoldoutFlow("ordinary", total)
	unknownTransport[0].Group["transport"] = "0"
	singleSYN := append(mixedHoldoutFlow("syn", total*3/4), mixedHoldoutFlow("ordinary", total/4)...)
	return []mixedDDoSReplayCase{
		{name: "syn_and_dns_flat", reference: ordinary, current: [2][]flowstore.PlanRow{synAndDNS, synAndDNS}, positive: true, wantVector: anomaly.DDoSMixedVectors},
		{name: "dns_and_ntp_flat", reference: ordinary, current: [2][]flowstore.PlanRow{dnsAndNTP, dnsAndNTP}, positive: true, wantVector: anomaly.DDoSMixedVectors},
		{name: "syn_and_dns_falling", reference: mixedHoldoutFlow("ordinary", total*3/2), current: [2][]flowstore.PlanRow{synAndDNS, synAndDNS}, positive: true, wantVector: anomaly.DDoSMixedVectors},
		{name: "mixed_one_window", reference: ordinary, current: [2][]flowstore.PlanRow{synAndDNS, ordinary}},
		{name: "mixed_background_steady", reference: synAndDNS, current: [2][]flowstore.PlanRow{synAndDNS, synAndDNS}},
		{name: "one_growing_vector", reference: steadyDNS, current: [2][]flowstore.PlanRow{synAndDNS, synAndDNS}},
		{name: "unknown_historical_transport", reference: unknownTransport, current: [2][]flowstore.PlanRow{synAndDNS, synAndDNS}, positive: true},
		{name: "single_large_vector", reference: ordinary, current: [2][]flowstore.PlanRow{singleSYN, singleSYN}, positive: true, wantVector: anomaly.DDoSSYN},
	}
}

func mixedHoldoutFlow(profile string, packets int) []flowstore.PlanRow {
	return benchmarkDDoSRows(benchmarkDDoSWindow{Profile: profile, Bytes: 100 * packets, Packets: packets,
		Records: 24, Addresses: 1, Sampling: 1, Complete: true})
}
