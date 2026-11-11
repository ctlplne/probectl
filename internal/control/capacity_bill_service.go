// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// checkCapacityAgreementBill owns no additional fairness slot or retained state.
// Its caller supplies the shared finite read operation and refreshes the exact
// originating transport credential before output. All financial/source/circuit
// authority and original receipts are re-read together after the calculation.
func (s *Server) checkCapacityAgreementBill(op capacityAgreementOperation, id string, input flow.CapacityBillRequest) (flow.CapacityAgreementBill, error) {
	none := flow.CapacityAgreementBill{}
	ctx := op.request.Context()
	parameters, err := capacityBillInput(input, op.budget.MemoryBytes/32)
	if err != nil {
		return none, err
	}
	before, err := s.capacityBillSnapshot(ctx, op, id, input, parameters, nil, nil)
	if err != nil {
		return none, err
	}
	history, available := flowstore.CounterHistoryOf(s.flowStore)
	if !available {
		return none, flowstore.ErrCounterHistoryUnavailable
	}
	query, err := capacityBillCounterQuery(before, parameters, flowstore.CounterBudget{MemoryBytes: op.budget.MemoryBytes / 4, WorkUnits: op.budget.ReadBytes, Timeout: op.budget.ExecutionLimit})
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
	if _, err := s.capacityBillSnapshot(ctx, op, id, input, parameters, &before, rows); err != nil {
		return none, err
	}
	window := flow.CapacityMeasurementWindow{From: before.period.From, To: before.period.To, MaximumPollGap: parameters.gap, MemoryBytes: op.budget.MemoryBytes / 2, WorkUnits: op.budget.MemoryBytes}
	members, err := measureCapacityBillMembers(ctx, before, rows, window, op.budget.MemoryBytes/4)
	if err != nil {
		return none, err
	}
	calculation := window
	calculation.MemoryBytes = op.budget.MemoryBytes / 2
	calculation.WorkUnits = op.budget.MemoryBytes
	percentile, err := flow.CalculateCapacityMeasuredP95(ctx, calculation, before.agreement.Definition.Direction, members)
	if err != nil {
		return none, err
	}
	bill, err := flow.CheckCapacityMeasuredBill(ctx, before.agreement.Definition, percentile, input.Invoiced, op.budget.MemoryBytes/8, op.budget.MemoryBytes/8)
	if err != nil {
		return none, err
	}
	after, err := s.capacityBillSnapshot(ctx, op, id, input, parameters, &before, rows)
	if err != nil {
		return none, err
	}
	result := flow.CapacityAgreementBill{Agreement: after.agreement, Period: after.period, MaximumPollGap: parameters.gap.String(), Percentile: percentile.Result(), Bill: bill,
		Members: make([]flow.CapacityBillMember, 0, len(after.members)), AsOf: after.asOf, MembershipBasis: "current_member_set_applied_to_complete_period"}
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
		result.Members = append(result.Members, flow.CapacityBillMember{ContextID: member.target.Scope.ContextID, DeviceID: member.target.Source.DeviceID,
			InterfaceID: member.target.InterfaceID, IfIndex: member.target.IfIndex, PhysicalMaxBPS: strconv.FormatUint(member.maximum, 10), ObservedNotBefore: notBefore})
	}
	return result, ctx.Err()
}

func capacityBillRowsInWindow(rows []flowstore.CounterRow, query flowstore.CounterQuery) error {
	for _, row := range rows {
		if row.PollStartedAt.Before(query.From) || row.PollStartedAt.After(query.To) {
			return flowstore.ErrCounterHistoryInput
		}
	}
	return nil
}

func measureCapacityBillMembers(ctx context.Context, plan capacityBillPlan, rows []flowstore.CounterRow, window flow.CapacityMeasurementWindow, retainedBytes int64) ([]flow.CapacityMeasuredMember, error) {
	if int64(len(rows)) > retainedBytes/1024 || int64(len(plan.members)) > retainedBytes/4096 {
		return nil, flowstore.ErrCounterHistoryBudget
	}
	bySource := make(map[capacityBillSourceKey]int, len(plan.members))
	points := make([][]flow.CapacityCounterObservation, len(plan.members))
	for i, member := range plan.members {
		bySource[capacityBillSource(member.target.Source, member.target.IfIndex)] = i
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		i, owned := bySource[capacityBillSource(row.CounterSource, row.IfIndex)]
		if !owned {
			return nil, flowstore.ErrCounterHistoryInput
		}
		point, octets, err := capacityBillObservation(row)
		if err != nil {
			return nil, err
		}
		if octets {
			points[i] = append(points[i], point)
		}
	}
	measured := make([]flow.CapacityMeasuredMember, 0, len(plan.members))
	for i, member := range plan.members {
		source := flow.CapacityCounterSource{TenantID: plan.agreement.TenantID, ContextID: member.target.Source.ContextID, DeviceID: member.target.Source.DeviceID, InterfaceID: member.target.InterfaceID,
			AgentID: member.target.Source.AgentID, SourceRef: member.target.Source.SourceRef, SourceAssignedAt: member.target.Source.SourceAssignedAt, AgentAssignedAt: member.target.Source.AgentAssignedAt,
			InterfaceCreatedAt: member.target.CreatedAt, PhysicalMaxBPS: member.maximum}
		result, err := flow.MeasureCapacityCounterMember(ctx, source, window, points[i])
		if err != nil {
			return nil, err
		}
		points[i] = nil
		charge, err := result.RetainedMemoryBytes(ctx)
		if err != nil {
			return nil, err
		}
		if charge > retainedBytes {
			return nil, apierror.TooLarge("complete measured member grids exceed resource admission")
		}
		retainedBytes -= charge
		measured = append(measured, result)
	}
	return measured, nil
}

func capacityBillObservation(row flowstore.CounterRow) (flow.CapacityCounterObservation, bool, error) {
	point := flow.CapacityCounterObservation{PollStartedAt: row.PollStartedAt, PollCompletedAt: row.PollCompletedAt, Value: row.Value,
		UptimeTicks: row.UptimeTicks, DiscontinuityTicks: row.DiscontinuityTicks, UptimeKnown: row.UptimeKnown, DiscontinuityKnown: row.DiscontinuityKnown}
	switch row.Name {
	case "probectl.device.if.in.octets":
		point.Direction = "in"
	case "probectl.device.if.out.octets":
		point.Direction = "out"
	case "probectl.device.if.in.errors", "probectl.device.if.out.errors", "probectl.device.if.in.discards", "probectl.device.if.out.discards":
		return point, false, nil
	default:
		return point, false, flowstore.ErrCounterHistoryInput
	}
	switch row.Width {
	case 32:
		point.Width = 32
	case 64:
		point.Width = 64
	default:
		return point, false, flowstore.ErrCounterHistoryInput
	}
	return point, true, nil
}
