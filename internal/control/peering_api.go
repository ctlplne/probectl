// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
)

func peeringAPIRequest(tenant string, input flow.PeeringEstimateInput) (peeringEstimateRequest, error) {
	none := peeringEstimateRequest{}
	for _, id := range []string{tenant, input.ContextID, input.InterfaceID} {
		value, err := gouuid.Parse(id)
		if err != nil || value == gouuid.Nil || value.String() != id {
			return none, apierror.Validation("canonical owned tenant/context/interface identity is required")
		}
	}
	parseID := func(value string) (int64, error) {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != value {
			return 0, apierror.Validation("IX and IX LAN IDs must be positive exact decimal strings")
		}
		return id, nil
	}
	ix, err := parseID(input.IXID)
	if err != nil {
		return none, err
	}
	lan, err := parseID(input.LANID)
	if err != nil {
		return none, err
	}
	if input.PeerASN == 0 || (input.Direction != "inbound" && input.Direction != "outbound") {
		return none, apierror.Validation("nonzero peer ASN and inbound/outbound direction are required")
	}
	return peeringEstimateRequest{Target: peeringTarget{Scope: entity.Scope{TenantID: tenant, ContextID: input.ContextID}, InterfaceID: input.InterfaceID, PeerASN: input.PeerASN, IXID: ix, LANID: lan}, Direction: input.Direction, From: input.From, To: input.To, BucketSeconds: input.BucketSeconds, DataSeries: input.DataSeries}, nil
}

func peeringRateResponse(value flow.PeeringTrafficPercentile) flow.PeeringRateEstimate {
	return flow.PeeringRateEstimate{SelectedIntervalBytes: value.Bytes, BitsPerSecondNumerator: value.BitsPerSecondNumerator, BitsPerSecondDenominator: value.BitsPerSecondDenominator, Intervals: value.Intervals, Rank: value.Rank, Nonzero: value.Nonzero}
}

func projectPeeringResponse(result peeringEstimateResult) flow.PeeringEstimateResponse {
	target := result.Target
	out := flow.PeeringEstimateResponse{ContractVersion: "probectl.peering-estimate.v1", Preview: true,
		Target:    flow.PeeringEstimateTarget{ContextID: target.Target.Scope.ContextID, InterfaceID: target.Target.InterfaceID, RouterID: target.RouterID, PeerASN: target.Target.PeerASN, IXID: strconv.FormatInt(target.Target.IXID, 10), LANID: strconv.FormatInt(target.Target.LANID, 10), Eligible: target.Eligible, Reason: target.Reason, PrefixVersion: target.PrefixVersion, MemberVersion: target.MemberVersion, PrefixIDs: append([]string{}, target.PrefixIDs...), MemberIDs: append([]string{}, target.MembershipIDs...)},
		Direction: result.Direction, Reason: result.Reason, From: result.From, To: result.To, BucketSeconds: result.BucketSeconds, Source: result.Source,
		Coverage: flow.PeeringEstimateCoverage{ObservedIntervals: result.ObservedIntervals, ExpectedIntervals: result.ExpectedIntervals, CompleteObservedInputs: result.CompleteObservedInputs, CompleteClassification: result.CompleteClassification},
		Bytes:    maps.Clone(result.Bytes), Transit: make([]flow.PeeringTransitEstimate, 0, len(result.Transit)),
		Interpretation: "Hypothetical eligibility of observed routing inputs only. Unknown routing/interface volumes are excluded from known-eligible p95 and reported separately. No lossless-telemetry, live peering/session, forwarding-policy, cost or guaranteed-savings claim."}
	if !target.AsOf.IsZero() {
		value := target.AsOf
		out.Target.AsOf = &value
	}
	if !target.ValidUntil.IsZero() {
		value := target.ValidUntil
		out.Target.ValidUntil = &value
	}
	if out.Bytes == nil {
		out.Bytes = map[string]string{}
	}
	if result.P95 != nil {
		value := peeringRateResponse(*result.P95)
		out.P95 = &value
	}
	for _, value := range result.Transit {
		out.Transit = append(out.Transit, flow.PeeringTransitEstimate{InterfaceID: value.InterfaceID, P95: peeringRateResponse(value.P95)})
	}
	slices.SortFunc(out.Transit, func(a, b flow.PeeringTransitEstimate) int {
		return slices.Compare([]string{a.InterfaceID}, []string{b.InterfaceID})
	})
	return out
}

func (s *Server) runPeeringEstimate(ctx context.Context, actor *auth.Principal, input flow.PeeringEstimateInput) (flow.PeeringEstimateResponse, error) {
	none := flow.PeeringEstimateResponse{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	request, err := peeringAPIRequest(actor.TenantID, input)
	if err != nil {
		return none, err
	}
	result, err := s.estimatePeeringTraffic(ctx, actor, request)
	if err != nil {
		return none, err
	}
	return projectPeeringResponse(result), nil
}

func (s *Server) handlePeeringEstimate(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" {
		return apierror.Unauthorized("tenant identity required")
	}
	var input flow.PeeringEstimateInput
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &input); err != nil {
		return err
	}
	release, err := s.beginPeeringQuery(r.Context(), actor)
	if err != nil {
		if errors.Is(err, fairness.ErrQueryConcurrency) || errors.Is(err, fairness.ErrQueryBudget) {
			w.Header().Set("Retry-After", "1")
			return apierror.RateLimited("tenant peering query allowance exceeded; retry shortly")
		}
		return err
	}
	defer release()
	result, err := s.runPeeringEstimate(r.Context(), actor, input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) beginPeeringQuery(ctx context.Context, actor *auth.Principal) (func(), error) {
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeNativeFlow(ctx, actor); err != nil {
		return nil, err
	}
	if s.fairnessGate == nil {
		return nil, apierror.Unavailable("peering query admission is unavailable")
	}
	return s.fairnessGate.BeginQuery(ctx, actor.TenantID)
}
