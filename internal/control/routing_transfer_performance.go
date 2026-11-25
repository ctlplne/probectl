// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	routingImprovePerformance = "improve_performance"
	routingReduceCost         = "reduce_cost"
)

type routingTransferProbeRequest struct {
	Source                      store.RoutingProbeTest `json:"source"`
	Candidate                   store.RoutingProbeTest `json:"candidate"`
	From                        time.Time              `json:"from"`
	To                          time.Time              `json:"to"`
	Mode                        string                 `json:"mode"`
	MaximumCandidateLossPPM     uint32                 `json:"maximum_candidate_loss_ppm"`
	MaximumCandidateP95RTTNanos string                 `json:"maximum_candidate_p95_rtt_nanos"`
	MaximumAddedCharge          string                 `json:"maximum_added_charge"`
}

type routingTransferPerformance struct {
	routingTransferProbeObservations
	Mode                        string `json:"mode"`
	MaximumCandidateLossPPM     uint32 `json:"maximum_candidate_loss_ppm"`
	MaximumCandidateP95RTTNanos string `json:"maximum_candidate_p95_rtt_nanos"`
	MaximumAddedCharge          string `json:"maximum_added_charge"`
	Recommendation              string `json:"recommendation"`
	RecommendationReason        string `json:"recommendation_reason"`
	LossImprovement             string `json:"loss_improvement_ratio,omitempty"`
	P95RTTImprovementNanos      string `json:"p95_rtt_improvement_nanos,omitempty"`
}

type routingTransferPerformanceSelection struct {
	request     routingTransferProbeRequest
	maximumRTT  uint64
	maximumCost *big.Rat
}

var routingTransferChargeCeiling = regexp.MustCompile(`^(0|[1-9][0-9]{0,13})(\.[0-9]{1,8})?$`)

func (r routingTransferProbeRequest) selection() (routingTransferPerformanceSelection, error) {
	var out routingTransferPerformanceSelection
	if r.Mode != routingImprovePerformance && r.Mode != routingReduceCost {
		return out, apierror.Validation("choose improve_performance or reduce_cost")
	}
	if r.From.IsZero() || !r.To.After(r.From) || r.To.After(time.Now()) || r.MaximumCandidateLossPPM > 1000000 {
		return out, apierror.Validation("a closed probe window and a candidate loss ceiling of 0–1000000 ppm are required")
	}
	maximumRTT, err := strconv.ParseUint(r.MaximumCandidateP95RTTNanos, 10, 63)
	if err != nil || maximumRTT == 0 || strconv.FormatUint(maximumRTT, 10) != r.MaximumCandidateP95RTTNanos {
		return out, apierror.Validation("a positive integer candidate p95 RTT ceiling in nanoseconds is required")
	}
	if !routingTransferChargeCeiling.MatchString(r.MaximumAddedCharge) {
		return out, apierror.Validation("maximum_added_charge must be a nonnegative decimal in the agreements' currency")
	}
	maximumCost, ok := new(big.Rat).SetString(r.MaximumAddedCharge)
	if !ok {
		return out, apierror.Validation("maximum_added_charge is invalid")
	}
	r.From, r.To = r.From.UTC(), r.To.UTC()
	return routingTransferPerformanceSelection{request: r, maximumRTT: maximumRTT, maximumCost: maximumCost}, nil
}

func (s routingTransferPerformanceSelection) evaluate(observations routingTransferProbeObservations,
	estimate flow.RoutingTransferEstimate) routingTransferPerformance {
	r := s.request
	out := routingTransferPerformance{routingTransferProbeObservations: observations, Mode: r.Mode,
		MaximumCandidateLossPPM: r.MaximumCandidateLossPPM, MaximumCandidateP95RTTNanos: r.MaximumCandidateP95RTTNanos,
		MaximumAddedCharge: r.MaximumAddedCharge, Recommendation: "retain_current"}
	out.RecommendationReason = s.decision(&out, estimate)
	if out.RecommendationReason == "thresholds_met" {
		out.Recommendation = "move_prefix"
	}
	return out
}

func (s routingTransferPerformanceSelection) decision(out *routingTransferPerformance, estimate flow.RoutingTransferEstimate) string {
	if out.Status != "measured" || out.Source == nil || out.Candidate == nil {
		return "paired_performance_unknown"
	}
	a, b := out.Source, out.Candidate
	aLoss, aOK := new(big.Rat).SetString(a.LossRatio)
	bLoss, bOK := new(big.Rat).SetString(b.LossRatio)
	if !aOK || !bOK {
		return "paired_performance_unknown"
	}
	out.LossImprovement = new(big.Rat).Sub(aLoss, bLoss).RatString()
	if !b.Reachable || b.P95RTTNanos == nil {
		return "candidate_unreachable"
	}
	bRTT, err := strconv.ParseUint(*b.P95RTTNanos, 10, 63)
	if err != nil {
		return "paired_performance_unknown"
	}
	var aRTT uint64
	if a.Reachable && a.P95RTTNanos != nil {
		aRTT, err = strconv.ParseUint(*a.P95RTTNanos, 10, 63)
		if err != nil {
			return "paired_performance_unknown"
		}
		out.P95RTTImprovementNanos = strconv.FormatInt(int64(aRTT)-int64(bRTT), 10)
	}
	lossCeiling := big.NewRat(int64(s.request.MaximumCandidateLossPPM), 1000000)
	if bLoss.Cmp(lossCeiling) > 0 || bRTT > s.maximumRTT {
		return "candidate_exceeds_performance_ceiling"
	}
	if bLoss.Cmp(aLoss) > 0 || a.Reachable && (a.P95RTTNanos == nil || bRTT > aRTT) {
		return "candidate_regresses_performance"
	}
	cost, ok := new(big.Rat).SetString(estimate.NetChargeChange)
	if estimate.Status != "estimated" || estimate.Currency == "" || !ok {
		return "capacity_or_comparable_charges_unknown"
	}
	if cost.Cmp(s.maximumCost) > 0 {
		return "candidate_exceeds_charge_ceiling"
	}
	if s.request.Mode == routingReduceCost && cost.Sign() >= 0 {
		return "candidate_does_not_reduce_cost"
	}
	if s.request.Mode == routingImprovePerformance && a.Reachable && bLoss.Cmp(aLoss) == 0 && bRTT == aRTT {
		return "candidate_does_not_improve_performance"
	}
	return "thresholds_met"
}

type routingTransferPerformanceEvidence struct {
	selection routingTransferPerformanceSelection
	plan      routingTransferProbePlan
	result    routingTransferProbeObservations
}

func (s *Server) captureRoutingTransferPerformance(ctx context.Context, op capacityAgreementOperation, scope entity.Scope,
	ports routingTransferPorts, route routingTransferRoute, selection routingTransferPerformanceSelection) (routingTransferPerformanceEvidence, error) {
	var out routingTransferPerformanceEvidence
	err := s.withTopologyFailureSnapshot(ctx, op.actor, scope, op.budget, func(ctx context.Context, sc tenancy.Scope,
		record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		current, err := s.routingTransferRouteInScope(ctx, sc, scope, record, authorize, ports, route.prefix, op.budget)
		if err != nil {
			return err
		}
		if !route.matchesCurrent(current) {
			return apierror.Conflict("the exact route changed while reading upstream performance")
		}
		out, err = s.routingTransferPerformanceInScope(ctx, sc, op, scope, record, authorize, ports, current, selection)
		return err
	})
	return out, err
}

func (s *Server) routingTransferPerformanceInScope(ctx context.Context, sc tenancy.Scope, op capacityAgreementOperation,
	scope entity.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize, ports routingTransferPorts,
	route routingTransferRoute, selection routingTransferPerformanceSelection) (routingTransferPerformanceEvidence, error) {
	var out routingTransferPerformanceEvidence
	request := selection.request
	tests := [2]store.RoutingProbeTest{request.Source, request.Candidate}
	plan, err := s.routingTransferProbePlanInScope(ctx, sc, op, scope, record, authorize, ports, route, tests)
	if err != nil {
		return out, err
	}
	result, err := readRoutingTransferProbeObservationsInScope(ctx, sc, op, plan, request.From, request.To)
	if err != nil {
		return out, err
	}
	return routingTransferPerformanceEvidence{selection: selection, plan: plan, result: result}, nil
}

func (old routingTransferPerformanceEvidence) matchesCurrent(current routingTransferPerformanceEvidence) bool {
	if current.plan.validUntil.Before(old.plan.validUntil) || old.plan.bindings != current.plan.bindings ||
		old.plan.target != current.plan.target || !reflect.DeepEqual(old.result, current.result) {
		return false
	}
	for i, expected := range old.plan.tests {
		now := current.plan.tests[i]
		// A certificate renewal can extend the same live source. The
		// assignment epochs and executable definition must stay exact.
		expected.MeasurementIdentityUntil, now.MeasurementIdentityUntil = nil, nil
		if !reflect.DeepEqual(expected, now) {
			return false
		}
	}
	return true
}
