// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestRoutingTransferPerformanceWeighsLossLatencyCostAndCapacity(t *testing.T) {
	now := time.Now()
	base := routingTransferProbeRequest{Mode: routingImprovePerformance, From: now.Add(-time.Minute), To: now.Add(-time.Second),
		MaximumCandidateLossPPM: 250000, MaximumCandidateP95RTTNanos: "70", MaximumAddedCharge: "1.50"}
	cases := []struct {
		name, mode, status, cost, loss, latency, want string
	}{
		{"performance at exact charge ceiling", routingImprovePerformance, "estimated", "3/2", "1/4", "60", "thresholds_met"},
		{"cost above exact ceiling", routingImprovePerformance, "estimated", "1500001/1000000", "1/4", "60", "candidate_exceeds_charge_ceiling"},
		{"loss above ceiling", routingImprovePerformance, "estimated", "-5", "13/50", "60", "candidate_exceeds_performance_ceiling"},
		{"RTT above ceiling", routingImprovePerformance, "estimated", "-5", "1/4", "71", "candidate_exceeds_performance_ceiling"},
		{"cost savings require capacity", routingReduceCost, "unavailable", "-5", "1/4", "60", "capacity_or_comparable_charges_unknown"},
		{"cost savings require strict price reduction", routingReduceCost, "estimated", "0", "1/4", "60", "candidate_does_not_reduce_cost"},
		{"cost savings require performance", routingReduceCost, "estimated", "-5", "1/4", "65", "candidate_regresses_performance"},
		{"cost savings at same performance", routingReduceCost, "estimated", "-5", "1/4", "64", "thresholds_met"},
		{"unreachable handoff stays withheld", routingImprovePerformance, "estimated", "-5", "1", "", "candidate_unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := base
			request.Mode = tc.mode
			selection, err := request.selection()
			if err != nil {
				t.Fatal(err)
			}
			before := "64"
			a := &routingTransferProbeStats{Reachable: true, LossRatio: "1/4", P95RTTNanos: &before}
			b := &routingTransferProbeStats{Reachable: tc.latency != "", LossRatio: tc.loss}
			if b.Reachable {
				b.P95RTTNanos = &tc.latency
			}
			got := selection.evaluate(routingTransferProbeObservations{Status: "measured", Source: a, Candidate: b},
				flow.RoutingTransferEstimate{Status: tc.status, Currency: "USD", NetChargeChange: tc.cost})
			if got.RecommendationReason != tc.want || (got.Recommendation == "move_prefix") != (tc.want == "thresholds_met") {
				t.Fatalf("recommendation %s, reason %s, want %s", got.Recommendation, got.RecommendationReason, tc.want)
			}
		})
	}
	base.MaximumAddedCharge = "1e100000000"
	if _, err := base.selection(); err == nil {
		t.Fatal("unbounded exponent was accepted as an operator charge ceiling")
	}
}
