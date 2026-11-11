// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (s *Server) measureCapacityForecast(op capacityForecastOperation, input flow.CapacityForecastRequest) (flow.CapacityForecastMeasurement, error) {
	none := flow.CapacityForecastMeasurement{}
	ctx := op.request.Context()
	parameters, err := capacityForecastInput(ctx, input, op.budget)
	if err != nil {
		return none, err
	}
	before, err := s.capacityForecastSnapshot(ctx, op.actor, parameters, op.budget, nil, nil)
	if err != nil {
		return none, err
	}
	history, available := flowstore.CounterHistoryOf(s.flowStore)
	if !available {
		return none, flowstore.ErrCounterHistoryUnavailable
	}
	query, err := capacityBillCounterQuery(before, parameters.counter, flowstore.CounterBudget{MemoryBytes: op.budget.MemoryBytes / 4, WorkUnits: op.budget.ReadBytes, Timeout: op.budget.ExecutionLimit})
	if err != nil {
		return none, err
	}
	rows, err := history.CounterPoints(ctx, query)
	if err != nil {
		return none, err
	}
	if err := capacityBillRowsInWindow(rows, query); err != nil {
		return none, err
	}
	if _, err := s.capacityForecastSnapshot(ctx, op.actor, parameters, op.budget, &before, rows); err != nil {
		return none, err
	}
	window := flow.CapacityMeasurementWindow{From: parameters.from, To: parameters.to, MaximumPollGap: parameters.counter.gap, MemoryBytes: op.budget.MemoryBytes / 2, WorkUnits: op.budget.MemoryBytes}
	members, err := measureCapacityBillMembers(ctx, before, rows, window, op.budget.MemoryBytes/4)
	if err != nil {
		return none, err
	}
	label := parameters.target.InterfaceID
	if parameters.target.Kind == "circuit" {
		label = parameters.target.TagID + ":" + parameters.target.TagValue
	}
	forecasts, err := flow.ForecastCapacityMeasured(ctx, window, label, parameters.direction, parameters.capacity, parameters.until, members)
	if err != nil {
		return none, err
	}
	after, err := s.capacityForecastSnapshot(ctx, op.actor, parameters, op.budget, &before, rows)
	if err != nil {
		return none, err
	}
	result := flow.CapacityForecastMeasurement{Target: parameters.target, Members: []flow.CapacityBillMember{}, Forecasts: forecasts, MaximumPollGap: parameters.counter.gap.String(), MembershipBasis: "current_member_set_applied_to_complete_period", AsOf: after.asOf}
	for _, member := range after.members {
		if result.SourceValidUntil.IsZero() || member.target.ValidUntil.Before(result.SourceValidUntil) {
			result.SourceValidUntil = member.target.ValidUntil
		}
		notBefore := member.target.CreatedAt
		for _, at := range []time.Time{member.target.Source.SourceAssignedAt, member.target.Source.AgentAssignedAt} {
			if at.After(notBefore) {
				notBefore = at
			}
		}
		result.Members = append(result.Members, flow.CapacityBillMember{ContextID: member.target.Scope.ContextID, DeviceID: member.target.Source.DeviceID, InterfaceID: member.target.InterfaceID, IfIndex: member.target.IfIndex, PhysicalMaxBPS: strconv.FormatUint(member.maximum, 10), ObservedNotBefore: notBefore})
	}
	return result, ctx.Err()
}
