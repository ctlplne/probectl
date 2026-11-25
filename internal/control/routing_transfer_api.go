// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type routingTransferRequest struct {
	routingTransferBillingInput
	ContextID       string                       `json:"context_id"`
	Destination     string                       `json:"destination_prefix"`
	LocalPreference uint32                       `json:"local_preference"`
	ProbeComparison *routingTransferProbeRequest `json:"probe_comparison,omitempty"`
}

type routingTransferPolicy struct {
	Operation       string `json:"operation"`
	RouterID        string `json:"router_id"`
	ExactPrefix     string `json:"exact_prefix"`
	SourcePeer      string `json:"current_peer"`
	CandidatePeer   string `json:"candidate_peer"`
	CandidateASN    uint32 `json:"candidate_asn"`
	LocalPreference uint32 `json:"local_preference"`
}

type routingTransferResponse struct {
	ContextID     string                       `json:"context_id"`
	Prefix        string                       `json:"destination_prefix"`
	Estimate      flow.RoutingTransferEstimate `json:"estimate"`
	Policy        *routingTransferPolicy       `json:"policy,omitempty"`
	EstimateBasis string                       `json:"estimate_basis"`
	Performance   string                       `json:"performance_status"`
	Upstream      *routingTransferPerformance  `json:"upstream_performance,omitempty"`
	ValidUntil    time.Time                    `json:"source_valid_until"`
	check         func(context.Context) error
}

func (s *Server) handleRoutingTransferEstimate(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreementMode(r, false)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	ctx := op.request.Context()
	if deadline, ok := ctx.Deadline(); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(15 * time.Second))
	}
	var input routingTransferRequest
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	result, err := s.runRoutingTransferEstimate(ctx, op, input)
	if err != nil {
		return routingTransferAPIError(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return apierror.Unavailable("complete routing transfer estimate output is unavailable")
	}
	if int64(len(encoded)) >= op.budget.ResponseBytes || int64(len(encoded)) >= op.budget.MemoryBytes/16 {
		return apierror.TooLarge("complete routing transfer output exceeds resource admission")
	}
	current := s.resolvePrincipal(op.request)
	if current == nil {
		return unauthenticated(op.request)
	}
	if !auth.SamePrincipalAuthority(op.actor, current) {
		return apierror.Forbidden("credential authority changed; run a fresh routing transfer estimate")
	}
	if err := result.check(ctx); err != nil {
		return routingTransferAPIError(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, json.RawMessage(encoded))
	return nil
}

func (s *Server) runRoutingTransferEstimate(ctx context.Context, op capacityAgreementOperation, input routingTransferRequest) (_ routingTransferResponse, operationErr error) {
	finish := s.beginFlowOperation(ctx, "routing_transfer_estimate")
	defer func() { finish(operationErr) }()
	none := routingTransferResponse{}
	prefix, err := netip.ParsePrefix(input.Destination)
	if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.String() != input.Destination || input.LocalPreference == 0 {
		return none, apierror.Validation("an exact canonical prefix and proposed local preference are required")
	}
	scope := entity.Scope{TenantID: op.actor.TenantID, ContextID: input.ContextID}
	if canonical, err := scope.Normalize(); err != nil || canonical != scope {
		return none, apierror.Validation("a canonical routing context is required")
	}
	var selection routingTransferPerformanceSelection
	if input.ProbeComparison != nil {
		selection, err = input.ProbeComparison.selection()
		if err != nil {
			return none, err
		}
	}
	billing := input.routingTransferBillingInput
	plans, err := s.readRoutingTransferBillPlans(ctx, op, scope, billing, nil, nil)
	if err != nil {
		return none, err
	}
	ports := selectRoutingTransferPorts(scope, plans)
	route, err := s.authorizeRoutingTransferRoute(ctx, op.actor, scope, ports, prefix, op.budget)
	if err != nil {
		return none, err
	}
	if input.LocalPreference <= route.highestKnownPreference {
		return none, apierror.Validation("the proposed local preference must exceed the observed values for the exact route")
	}
	handoffs, rows, window, err := s.measureRoutingTransferHandoffs(ctx, op, scope, billing, plans)
	if err != nil {
		return none, err
	}
	sources, err := s.routingTransferExporterSources(ctx, op.actor, scope, ports.source, op.budget)
	if err != nil {
		return none, err
	}
	observed, err := s.readRoutingTransferFlows(ctx, scope, prefix, window, sources.sources, op.budget)
	if err != nil {
		return none, err
	}
	originals, err := s.readRoutingTransferOriginals(ctx, op.actor, scope, ports.source.Source.DeviceID, observed.originals, op.budget)
	if err != nil {
		return none, err
	}
	observed.originals = originals
	intervals, reason, err := buildRoutingTransferGrid(ctx, scope, ports.source, route, handoffs[0], observed, window)
	if err != nil {
		return none, err
	}
	result := routingTransferResponse{ContextID: scope.ContextID, Prefix: prefix.String(), EstimateBasis: plans.basis, Performance: "no_paired_upstream_measurement", ValidUntil: route.validUntil,
		Estimate: flow.RoutingTransferEstimate{From: window.From, To: window.To, Status: "unavailable", Reason: reason}}
	if sources.validUntil.Before(result.ValidUntil) {
		result.ValidUntil = sources.validUntil
	}
	for _, member := range plans.joined.members {
		if member.target.ValidUntil.Before(result.ValidUntil) {
			result.ValidUntil = member.target.ValidUntil
		}
	}
	if reason == "" {
		result.Estimate, err = flow.EstimateRoutingEgressTransfer(ctx, window, scope.ContextID, handoffs[0], handoffs[1], intervals)
		if err != nil {
			return none, err
		}
	}
	if result.Estimate.Status == "estimated" {
		result.Policy = &routingTransferPolicy{Operation: "set_inbound_local_preference_for_exact_prefix", RouterID: ports.source.Source.DeviceID,
			ExactPrefix: prefix.String(), SourcePeer: route.selected.String(), CandidatePeer: route.candidate.String(), CandidateASN: route.candidateASN,
			LocalPreference: input.LocalPreference}
	}
	var performance *routingTransferPerformanceEvidence
	if input.ProbeComparison != nil {
		if selection.request.From.Before(window.From) || selection.request.To.After(window.To) {
			return none, apierror.Validation("the probe comparison window must fall inside the routing transfer measurement window")
		}
		captured, err := s.captureRoutingTransferPerformance(ctx, op, scope, ports, route, selection)
		if err != nil {
			return none, err
		}
		performance = &captured
		comparison := selection.evaluate(captured.result, result.Estimate)
		result.Performance, result.Upstream = comparison.Status, &comparison
		result.ValidUntil = earlierRoutingProbeDeadline(result.ValidUntil, captured.plan.validUntil)
		if comparison.Recommendation != "move_prefix" {
			result.Policy = nil
		}
	}
	result.check = func(ctx context.Context) error {
		if err := s.recheckRoutingTransferEstimate(ctx, op, scope, billing, plans, ports, route, sources, originals, rows); err != nil {
			return err
		}
		if performance != nil {
			current, err := s.captureRoutingTransferPerformance(ctx, op, scope, ports, route, performance.selection)
			if err != nil {
				return err
			}
			if !performance.matchesCurrent(current) {
				return apierror.Conflict("the upstream probe evidence changed; run a fresh estimate")
			}
		}
		if !time.Now().Before(result.ValidUntil) {
			return apierror.Unavailable("routing transfer sources expired; retry")
		}
		return ctx.Err()
	}
	return result, ctx.Err()
}

func (s *Server) recheckRoutingTransferEstimate(ctx context.Context, op capacityAgreementOperation, scope entity.Scope,
	input routingTransferBillingInput, before routingTransferBillPlans, ports routingTransferPorts, route routingTransferRoute,
	sources routingTransferExporterPlan, originals routingTransferFlowEvidence, rows []flowstore.CounterRow) error {
	if _, err := s.readRoutingTransferBillPlans(ctx, op, scope, input, &before, rows); err != nil {
		return err
	}
	currentRoute, err := s.authorizeRoutingTransferRoute(ctx, op.actor, scope, ports, route.prefix, op.budget)
	if err != nil {
		return err
	}
	if !route.matchesCurrent(currentRoute) {
		return apierror.Unavailable("owned routing choices changed; retry")
	}
	currentSources, err := s.routingTransferExporterSources(ctx, op.actor, scope, ports.source, op.budget)
	if err != nil {
		return err
	}
	if !sources.matchesCurrent(currentSources) {
		return apierror.Unavailable("owned exporter assignments or leases changed; retry")
	}
	after, err := s.readRoutingTransferOriginals(ctx, op.actor, scope, ports.source.Source.DeviceID, originals, op.budget)
	if err != nil {
		return err
	}
	if !originals.matchesCurrent(after) {
		return apierror.Unavailable("original flow authority or selected prefixes changed; retry")
	}
	return ctx.Err()
}

func routingTransferAPIError(err error) error {
	if domain, ok := apierror.As(err); ok {
		return domain
	}
	switch {
	case errors.Is(err, flow.ErrFailureTrafficBudget), errors.Is(err, flowstore.ErrExplorerBudget),
		errors.Is(err, store.ErrBGPRoutingBudget), errors.Is(err, entity.ErrInterfaceRoleBudget):
		return apierror.TooLarge("complete routing transfer input exceeds resource admission")
	case errors.Is(err, entity.ErrScopeMismatch):
		return apierror.NotFound("the owned routing transfer source is unavailable")
	case errors.Is(err, entity.ErrInvalidClaim):
		return apierror.Validation("two distinct, canonical test and agent selections are required")
	default:
		return capacityBillAPIError(err)
	}
}
