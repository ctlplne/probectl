// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"
	"time"

	guuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The request chooses two recorded agreements and the exact physical handoffs
// within their current membership. Physical bounds only limit the simulation.
// The candidate speed still requires independent, original SNMP evidence.
type routingTransferBillingSelection struct {
	AgreementID string                       `json:"agreement_id"`
	Version     string                       `json:"agreement_version"`
	EgressID    string                       `json:"egress_interface_id"`
	Bounds      []flow.CapacityPhysicalBound `json:"physical_bounds"`
}

type routingTransferBillingInput struct {
	At             string                          `json:"billing_at,omitempty"`
	ObservedFrom   string                          `json:"observed_from,omitempty"`
	ObservedTo     string                          `json:"observed_to,omitempty"`
	MaximumPollGap string                          `json:"maximum_poll_gap"`
	Source         routingTransferBillingSelection `json:"source"`
	Candidate      routingTransferBillingSelection `json:"candidate"`
}

type routingTransferBillPlans struct {
	selection [2]routingTransferBillingSelection
	plan      [2]capacityBillPlan
	joined    capacityCounterPlan
	gap       time.Duration
	basis     string
}

func routingTransferBillPlanMatchesCurrent(previous, current capacityBillPlan) bool {
	if !sameCapacityBillPlan(previous, current) {
		return false
	}
	for i, member := range previous.members {
		if current.members[i].target.ValidUntil.Before(member.target.ValidUntil) {
			return false
		}
	}
	return true
}

func routingTransferBillingSelections(input routingTransferBillingInput) [2]routingTransferBillingSelection {
	return [2]routingTransferBillingSelection{input.Source, input.Candidate}
}

func (s *Server) readRoutingTransferBillPlans(ctx context.Context, op capacityAgreementOperation, scope entity.Scope,
	input routingTransferBillingInput, previous *routingTransferBillPlans, rows []flowstore.CounterRow) (routingTransferBillPlans, error) {
	var out routingTransferBillPlans
	if op.actor == nil {
		return out, entity.ErrScopeMismatch
	}
	if err := s.currentCapacityAgreementActor(ctx, op.actor, false); err != nil {
		return out, err
	}
	err := s.withTopologyFailureSnapshot(ctx, op.actor, scope, op.budget, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		var err error
		out, err = s.routingTransferBillPlansInScope(ctx, sc, record, authorize, op, scope, input, previous, rows)
		return err
	})
	return out, err
}

func (s *Server) routingTransferBillPlansInScope(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord,
	authorize topologyFailureAuthorize, op capacityAgreementOperation, scope entity.Scope,
	input routingTransferBillingInput, previous *routingTransferBillPlans, rows []flowstore.CounterRow) (routingTransferBillPlans, error) {
	none := routingTransferBillPlans{}
	if op.actor == nil || scope.TenantID != op.actor.TenantID || input.Source.AgreementID == input.Candidate.AgreementID ||
		input.Source.EgressID == input.Candidate.EgressID {
		return none, apierror.Validation("select two distinct tenant-owned agreements and handoffs")
	}
	period, err := observedRoutingTransferPeriod(input)
	if err != nil {
		return none, err
	}
	out := routingTransferBillPlans{selection: routingTransferBillingSelections(input), basis: "complete_billing_period"}
	at := input.At
	if period != nil {
		out.basis = period.BoundaryPolicy
		at = input.ObservedFrom
	}
	requests := [2]flow.CapacityBillRequest{}
	parameters := [2]capacityBillParameters{}
	for i, selected := range out.selection {
		for _, id := range []string{selected.AgreementID, selected.EgressID} {
			canonical, err := guuid.Parse(id)
			if err != nil || canonical == guuid.Nil || canonical.String() != id {
				return none, apierror.Validation("select canonical agreement and interface identities")
			}
		}
		request := flow.CapacityBillRequest{Version: selected.Version, At: at, MaximumPollGap: input.MaximumPollGap, PhysicalBounds: selected.Bounds}
		params, err := capacityBillInput(request, op.budget.MemoryBytes/32)
		if err != nil {
			return none, err
		}
		requests[i], parameters[i] = request, params
	}
	out.gap = parameters[0].gap
	current, err := readCurrentUserAuthorityScope(ctx, sc, op.actor.UserID)
	if err != nil {
		return none, err
	}
	ctx, principal, err := current.requestContext(ctx, op.actor)
	if err != nil {
		return none, err
	}
	for i, selected := range out.selection {
		plan, err := s.routingTransferBillPlanInScope(ctx, sc, op, principal, selected.AgreementID, requests[i], parameters[i], period)
		if err != nil {
			return none, err
		}
		if plan.agreement.Version != plan.agreement.CurrentVersion {
			return none, apierror.Conflict("refresh the agreement revision before recommending a change")
		}
		if err := authorizeRoutingTransferHandoff(ctx, scope, record, authorize, selected.EgressID, plan.members); err != nil {
			return none, err
		}
		if previous != nil && !routingTransferBillPlanMatchesCurrent(previous.plan[i], plan) {
			return none, apierror.Unavailable("capacity terms, membership or source authority changed; retry")
		}
		out.plan[i] = plan
	}
	joined, err := joinRoutingTransferBillPlans(out.plan)
	if err != nil {
		return none, err
	}
	out.joined = joined
	if err := validateCapacityCounterRows(ctx, sc, store.NewDeviceCounterCaptures(s.pool), joined, rows, op.budget.MemoryBytes/8); err != nil {
		return none, err
	}
	return out, ctx.Err()
}

// Operators can compare both tariffs on a recent closed measurement window,
// including providers whose billing calendars differ. The caller labels the
// result as a counterfactual under those rates rather than an actual bill.
func observedRoutingTransferPeriod(input routingTransferBillingInput) (*flow.CapacityBillingPeriod, error) {
	if input.ObservedFrom == "" && input.ObservedTo == "" {
		return nil, nil
	}
	from, err := topologyFailureClock(input.ObservedFrom)
	if err != nil {
		return nil, err
	}
	to, err := topologyFailureClock(input.ObservedTo)
	if err != nil {
		return nil, err
	}
	span := to.Sub(from)
	if input.At != "" || span <= 0 || !from.Add(span).Equal(to) || to.After(time.Now().UTC()) {
		return nil, apierror.Validation("choose either an instant in a completed billing period or one closed observation window")
	}
	return &flow.CapacityBillingPeriod{From: from, To: to, Timezone: "UTC", BoundaryPolicy: "observed_window_at_recorded_unit_rates"}, nil
}

func (s *Server) routingTransferBillPlanInScope(ctx context.Context, sc tenancy.Scope, op capacityAgreementOperation, principal *auth.Principal,
	id string, input flow.CapacityBillRequest, parameters capacityBillParameters, observed *flow.CapacityBillingPeriod) (capacityBillPlan, error) {
	if observed == nil {
		return s.capacityBillPlanInScope(ctx, sc, op, principal, id, input, parameters)
	}
	none := capacityBillPlan{}
	agreement, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, id, input.Version, nil)
	if err != nil {
		return none, err
	}
	if !agreement.TargetPresent {
		return none, apierror.Unavailable("the recorded agreement target has retired")
	}
	for _, at := range []time.Time{observed.From, observed.To.Add(-time.Nanosecond)} {
		effective, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, id, "", &at)
		if err != nil {
			return none, err
		}
		if effective.Version != agreement.Version {
			return none, apierror.Validation("recorded agreement terms must cover the observation window")
		}
	}
	plan, err := s.capacityCounterPlanInScope(ctx, sc, principal, agreement.Definition.Target, *observed, parameters, op.budget)
	if err != nil {
		return none, err
	}
	return capacityBillPlan{capacityCounterPlan: plan, agreement: agreement}, nil
}

func authorizeRoutingTransferHandoff(ctx context.Context, scope entity.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize,
	egress string, members []capacityBillMemberPlan) error {
	for _, member := range members {
		p := member.target
		if p.Scope == scope && p.InterfaceID == egress {
			if err := authorize(ctx, record, p.Source.DeviceID); err != nil {
				return err
			}
			return authorize(ctx, record, p.InterfaceID)
		}
	}
	return apierror.NotFound("handoff is outside the selected agreement or routing context")
}

func joinRoutingTransferBillPlans(plans [2]capacityBillPlan) (capacityCounterPlan, error) {
	var out capacityCounterPlan
	from, to := plans[0].period.From, plans[0].period.To
	if !plans[1].period.From.Equal(from) || !plans[1].period.To.Equal(to) {
		return out, apierror.Validation("both agreements must cover the same completed comparison window")
	}
	if to.After(time.Now().UTC()) {
		return out, apierror.Validation("use a completed billing window")
	}
	out = capacityCounterPlan{tenant: plans[0].tenant, period: plans[0].period, asOf: plans[0].asOf}
	seen := map[capacityBillMemberKey]bool{}
	for _, plan := range plans {
		if plan.tenant != out.tenant {
			return capacityCounterPlan{}, tenancy.ErrNoTenant
		}
		for _, member := range plan.members {
			key := capacityBillMemberKey{member.target.Scope.ContextID, member.target.InterfaceID}
			if seen[key] {
				return capacityCounterPlan{}, apierror.Validation("the two agreements share a measured circuit member")
			}
			seen[key] = true
			out.members = append(out.members, member)
		}
	}
	return out, nil
}

func routingTransferHandoffs(plans routingTransferBillPlans, measured []flow.CapacityMeasuredMember, candidateSpeed uint64) [2]flow.RoutingTransferHandoff {
	split := len(plans.plan[0].members)
	return [2]flow.RoutingTransferHandoff{
		{Agreement: plans.plan[0].agreement, EgressID: plans.selection[0].EgressID, Members: measured[:split]},
		{Agreement: plans.plan[1].agreement, EgressID: plans.selection[1].EgressID, Members: measured[split:], EgressSpeedBPS: candidateSpeed},
	}
}

func (s *Server) measureRoutingTransferHandoffs(ctx context.Context, op capacityAgreementOperation, scope entity.Scope,
	input routingTransferBillingInput, plans routingTransferBillPlans) ([2]flow.RoutingTransferHandoff, []flowstore.CounterRow, flow.CapacityMeasurementWindow, error) {
	none := [2]flow.RoutingTransferHandoff{}
	empty := flow.CapacityMeasurementWindow{}
	history, ok := flowstore.CounterHistoryOf(s.flowStore)
	if !ok {
		return none, nil, empty, flowstore.ErrCounterHistoryUnavailable
	}
	budget := flowstore.CounterBudget{MemoryBytes: op.budget.MemoryBytes / 4, WorkUnits: op.budget.ReadBytes / 2, Timeout: op.budget.ExecutionLimit}
	query, err := capacityBillCounterQuery(plans.joined, capacityBillParameters{gap: plans.gap}, budget)
	if err != nil {
		return none, nil, empty, err
	}
	query.To = query.To.Add(min(plans.gap, max(0, time.Since(query.To))))
	rows, err := history.CounterPoints(ctx, query)
	if err != nil {
		return none, nil, empty, err
	}
	if err := capacityBillRowsInWindow(rows, query); err != nil {
		return none, nil, empty, err
	}
	if _, err := s.readRoutingTransferBillPlans(ctx, op, scope, input, &plans, rows); err != nil {
		return none, nil, empty, err
	}
	period := plans.joined.period
	window := flow.CapacityMeasurementWindow{From: period.From, To: period.To, MaximumPollGap: plans.gap,
		MemoryBytes: op.budget.MemoryBytes / 2, WorkUnits: op.budget.MemoryBytes}
	plans.joined.members = slices.Clone(plans.joined.members)
	candidate := selectRoutingTransferPorts(scope, plans).candidate
	speed := topologyFailureCounterSpeeds(rows)[capacityBillSource(candidate.Source, candidate.IfIndex)]
	if speed == 0 {
		return none, nil, empty, apierror.Unavailable("the candidate handoff needs a verified stable line rate")
	}
	for i, member := range plans.joined.members {
		if member.target.InterfaceID == candidate.InterfaceID && member.target.Scope == candidate.Scope {
			plans.joined.members[i].maximum = min(member.maximum, speed)
			break
		}
	}
	measured, err := measureCapacityBillMembers(ctx, plans.joined, rows, window, op.budget.MemoryBytes/4)
	if err != nil {
		return none, nil, empty, err
	}
	return routingTransferHandoffs(plans, measured, speed), rows, window, ctx.Err()
}
