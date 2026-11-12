// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (s *Server) measureCapacityForecast(op capacityForecastOperation, input flow.CapacityForecastRequest) (_ flow.CapacityForecastMeasurement, operationErr error) {
	none := flow.CapacityForecastMeasurement{}
	ctx := op.request.Context()
	finish := s.beginFlowOperation(ctx, "capacity_forecast")
	phase := "input"
	defer func() {
		finish(operationErr)
		s.logCapacityForecastFailure(ctx, phase, operationErr)
	}()
	parameters, err := capacityForecastInput(ctx, input, op.budget)
	if err != nil {
		return none, err
	}
	phase = "current_source"
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
	phase = "counter_history"
	rows, err := history.CounterPoints(ctx, query)
	if err != nil {
		return none, err
	}
	if err := capacityBillRowsInWindow(rows, query); err != nil {
		return none, err
	}
	phase = "original_receipts"
	if _, err := s.capacityForecastSnapshot(ctx, op.actor, parameters, op.budget, &before, rows); err != nil {
		return none, err
	}
	workUnits, err := flow.CapacityForecastWorkUnits(op.budget.MemoryBytes)
	if err != nil {
		return none, err
	}
	window := flow.CapacityMeasurementWindow{From: parameters.from, To: parameters.to, MaximumPollGap: parameters.counter.gap, MemoryBytes: op.budget.MemoryBytes / 2, WorkUnits: workUnits}
	phase = "member_measurement"
	members, err := measureCapacityBillMembers(ctx, before, rows, window, op.budget.MemoryBytes/4)
	if err != nil {
		return none, err
	}
	label := parameters.target.InterfaceID
	if parameters.target.Kind == "circuit" {
		label = parameters.target.TagID + ":" + parameters.target.TagValue
	}
	phase = "forecast_model"
	forecasts, err := flow.ForecastCapacityMeasured(ctx, window, label, parameters.direction, parameters.capacity, parameters.until, members)
	if err != nil {
		return none, err
	}
	phase = "publication_source"
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

func (s *Server) logCapacityForecastFailure(ctx context.Context, phase string, err error) {
	if err == nil {
		return
	}
	// Fixed phases and error classes expose no counter values, source
	// identities, SQL text or credential material. Keep the original whole
	// workload; diagnostics must not turn a refusal into success.
	state := ""
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		state = postgres.SQLState()
	}
	s.log.WarnContext(ctx, "capacity forecast measurement failed", "phase", phase,
		"outcome", flowOperationOutcome(err), "sqlstate", state,
		"deadline_exceeded", errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded),
		"receipt_unavailable", errors.Is(err, store.ErrCounterCaptureUnavailable))
}
