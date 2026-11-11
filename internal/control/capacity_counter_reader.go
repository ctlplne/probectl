// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// A caller selects canonical inventory and explicit physical assumptions, never
// a counter population, source assignment, uptime label or certificate identity.
type capacityCounterSelection struct {
	Scope          entity.Scope
	InterfaceID    string
	PhysicalMaxBPS uint64
}

func sameCapacityCounterInterface(a, b store.DeviceCounterInterface) bool {
	return a.Scope == b.Scope && a.InterfaceID == b.InterfaceID && a.IfIndex == b.IfIndex && a.Generation == b.Generation &&
		a.Source.ContextID == b.Source.ContextID && a.Source.DeviceID == b.Source.DeviceID && a.Source.AgentID == b.Source.AgentID && a.Source.SourceRef == b.Source.SourceRef &&
		a.Source.SourceAssignedAt.Equal(b.Source.SourceAssignedAt) && a.Source.AgentAssignedAt.Equal(b.Source.AgentAssignedAt)
}

func (s *Server) capacityCounterSnapshot(ctx context.Context, actor *auth.Principal, selected capacityCounterSelection, previous *store.DeviceCounterInterface, rows []flowstore.CounterRow, budget flowstore.CounterBudget) (store.DeviceCounterInterface, error) {
	none := store.DeviceCounterInterface{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if s.pool == nil || selected.Scope.TenantID != actor.TenantID || budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || budget.Timeout <= 0 {
		return none, apierror.Forbidden("current capacity tenant and source admission are required")
	}
	if s.requireMFA && !actor.MFASatisfied {
		return none, apierror.Forbidden("multi-factor authentication required")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("current capacity tenant is inactive")
	}
	var out store.DeviceCounterInterface
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, selected.Scope.ContextID)
		if err != nil {
			return err
		}
		for _, permission := range []string{ai.PermEntitiesRead, ai.PermMetricsRead} {
			if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
				return err
			}
		}
		reader := store.NewDeviceCounterCaptures(s.pool)
		out, err = reader.CurrentInterfaceInScope(ctx, sc, selected.Scope, selected.InterfaceID)
		if err != nil {
			return err
		}
		if previous != nil && !sameCapacityCounterInterface(*previous, out) {
			return apierror.Unavailable("capacity source or lifecycle changed; retry")
		}
		return validateCapacityCounterReceipts(ctx, sc, reader, out, rows, budget)
	})
	if err != nil {
		return none, err
	}
	return out, nil
}

func validateCapacityCounterReceipts(ctx context.Context, sc tenancy.Scope, reader *store.DeviceCounterCaptures, target store.DeviceCounterInterface, rows []flowstore.CounterRow, budget flowstore.CounterBudget) error {
	// Bound both the retained receipt map and DB work before creating it. A
	// complete read fails admission rather than dropping old polls or members.
	if int64(len(rows)) > budget.MemoryBytes/4096 || int64(len(rows)) > budget.WorkUnits/4096 {
		return flowstore.ErrCounterHistoryBudget
	}
	witnesses := make(map[[32]byte]store.DeviceCounterCapture)
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if row.TenantID != target.Scope.TenantID || row.IfIndex != target.IfIndex ||
			row.ContextID != target.Source.ContextID || row.DeviceID != target.Source.DeviceID || row.AgentID != target.Source.AgentID || row.SourceRef != target.Source.SourceRef ||
			!row.SourceAssignedAt.Equal(target.Source.SourceAssignedAt) || !row.AgentAssignedAt.Equal(target.Source.AgentAssignedAt) {
			return entity.ErrScopeMismatch
		}
		input := entity.CounterCaptureInput{ConfiguredTarget: row.SourceRef, PollStartedAt: row.PollStartedAt, PollCompletedAt: row.PollCompletedAt, PointCount: row.Population}
		key, err := entity.CounterCaptureKey(row.TenantID, row.AgentID, row.RawDigest, input)
		if err != nil || key != row.CaptureKey || row.Width != 32 && row.Width != 64 {
			return flowstore.ErrCounterHistoryInput
		}
		witness, found := witnesses[row.CaptureKey]
		if !found {
			var err error
			witness, err = reader.LookupWitnessInScope(ctx, sc, row.AgentID, row.RawDigest, input)
			if err != nil {
				return err
			}
			witnesses[row.CaptureKey] = witness
		}
		if witness.Key != row.CaptureKey || witness.Scope != target.Scope || witness.DeviceID != row.DeviceID || witness.SenderSerial != row.SenderSerial ||
			!witness.CapturedAt.Equal(row.CapturedAt) || !witness.SourceAssignedAt.Equal(row.SourceAssignedAt) || !witness.AgentAssignedAt.Equal(row.AgentAssignedAt) {
			return store.ErrCounterCaptureUnavailable
		}
	}
	return nil
}

// readCapacityCounterMember consumes retained exact observations, not legacy
// float metrics. Public adapters must own the shared deadline/fairness slot and
// refresh the exact originating credential and complete circuit/financial
// authority after all member reads. A principal copy is not a token/session.
func (s *Server) readCapacityCounterMember(ctx context.Context, actor *auth.Principal, selected capacityCounterSelection, window flow.CapacityMeasurementWindow, budget flowstore.CounterBudget) (flow.CapacityMeasuredMember, error) {
	none := flow.CapacityMeasuredMember{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if budget.Timeout <= 0 || window.MaximumPollGap <= 0 || !window.To.After(window.From) || window.MemoryBytes <= 0 || window.WorkUnits <= 0 {
		return none, flowstore.ErrCounterHistoryInput
	}
	ctx, cancel := context.WithTimeout(ctx, budget.Timeout)
	defer cancel()
	target, err := s.capacityCounterSnapshot(ctx, actor, selected, nil, nil, budget)
	if err != nil {
		return none, err
	}
	history, available := flowstore.CounterHistoryOf(s.flowStore)
	if !available {
		return none, flowstore.ErrCounterHistoryUnavailable
	}
	from := window.From.Add(-window.MaximumPollGap)
	if !from.Before(window.From) || from.UnixNano() <= 0 || !time.Unix(0, from.UnixNano()).Equal(from) {
		return none, flowstore.ErrCounterHistoryInput
	}
	rows, err := history.CounterPoints(ctx, flowstore.CounterQuery{TenantID: actor.TenantID, From: from, To: window.To,
		Sources: []flowstore.CounterSelector{{CounterSource: target.Source, IfIndexes: []uint32{target.IfIndex}}}, Budget: budget})
	if err != nil {
		return none, err // no calculation over a backend prefix, even after late failure
	}
	if _, err := s.capacityCounterSnapshot(ctx, actor, selected, &target, rows, budget); err != nil {
		return none, err
	}
	if int64(len(rows)) > window.MemoryBytes/8192 || int64(len(rows)) > window.WorkUnits/8192 {
		return none, flowstore.ErrCounterHistoryBudget
	}
	observations := make([]flow.CapacityCounterObservation, 0, len(rows))
	for _, row := range rows {
		direction := ""
		switch row.Name {
		case "probectl.device.if.in.octets":
			direction = "in"
		case "probectl.device.if.out.octets":
			direction = "out"
		default:
			continue
		}
		var width uint8
		switch row.Width {
		case 32:
			width = 32
		case 64:
			width = 64
		default:
			return none, flowstore.ErrCounterHistoryInput
		}
		observations = append(observations, flow.CapacityCounterObservation{Direction: direction, PollStartedAt: row.PollStartedAt, PollCompletedAt: row.PollCompletedAt,
			Value: row.Value, Width: width, UptimeTicks: row.UptimeTicks, DiscontinuityTicks: row.DiscontinuityTicks, UptimeKnown: row.UptimeKnown, DiscontinuityKnown: row.DiscontinuityKnown})
	}
	source := flow.CapacityCounterSource{TenantID: actor.TenantID, ContextID: target.Source.ContextID, DeviceID: target.Source.DeviceID, InterfaceID: target.InterfaceID,
		AgentID: target.Source.AgentID, SourceRef: target.Source.SourceRef, SourceAssignedAt: target.Source.SourceAssignedAt, AgentAssignedAt: target.Source.AgentAssignedAt, PhysicalMaxBPS: selected.PhysicalMaxBPS}
	result, err := flow.MeasureCapacityCounterMember(ctx, source, window, observations)
	if err != nil {
		return none, err
	}
	if _, err := s.capacityCounterSnapshot(ctx, actor, selected, &target, rows, budget); err != nil {
		return none, err
	}
	return result, ctx.Err()
}
