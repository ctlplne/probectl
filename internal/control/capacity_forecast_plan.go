// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type capacityForecastParameters struct {
	counter             capacityBillParameters
	from, to, until     time.Time
	target              flow.CapacityTarget
	direction, capacity string
}

func capacityForecastInput(ctx context.Context, input flow.CapacityForecastRequest, budget flowstore.ExplorerBudget) (capacityForecastParameters, error) {
	none := capacityForecastParameters{}
	parameters, err := capacityCounterInput(input.MaximumPollGap, input.PhysicalBounds, budget.MemoryBytes/32)
	if err != nil {
		return none, err
	}
	values := []time.Time{}
	for _, text := range []string{input.From, input.To, input.Until} {
		at, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || at.UnixNano() <= 0 || !time.Unix(0, at.UnixNano()).Equal(at) {
			return none, apierror.Validation("training and horizon bounds require exact supported RFC3339 instants")
		}
		values = append(values, at)
	}
	from, to, until := values[0], values[1], values[2]
	if !to.After(from) || !until.After(to) || !from.Add(to.Sub(from)).Equal(to) || !from.Add(until.Sub(from)).Equal(until) {
		return none, apierror.Validation("complete training bounds and a later explicit forecast horizon are required")
	}
	switch input.Direction {
	case "in", "out", "max_directional_percentiles", "interval_max", "interval_sum":
	default:
		return none, apierror.Validation("a supported measured direction is required")
	}
	target := input.Target
	var ids []string
	switch target.Kind {
	case "interface":
		if target.TagID != "" || target.TagValue != "" {
			return none, apierror.Validation("interface and circuit selection cannot be combined")
		}
		ids = []string{target.ContextID, target.InterfaceID}
	case "circuit":
		if target.ContextID != "" || target.InterfaceID != "" {
			return none, apierror.Validation("interface and circuit selection cannot be combined")
		}
		ids = []string{target.TagID}
	default:
		return none, apierror.Validation("a canonical interface or tagged circuit is required")
	}
	for _, id := range ids {
		parsed, err := gouuid.Parse(id)
		if err != nil || parsed == gouuid.Nil || parsed.String() != id {
			return none, apierror.Validation("canonical current tenant inventory IDs are required")
		}
	}
	if err := flow.ValidateCapacityForecastThreshold(ctx, input.CapacityBPS, budget.MemoryBytes/32, budget.ReadBytes/32); err != nil {
		return none, apierror.Validation("a positive exact decimal forecast threshold within arithmetic admission is required")
	}
	return capacityForecastParameters{counter: parameters, from: from, to: to, until: until, target: target, direction: input.Direction, capacity: input.CapacityBPS}, nil
}

func (s *Server) capacityForecastSnapshot(ctx context.Context, actor *auth.Principal, parameters capacityForecastParameters, budget flowstore.ExplorerBudget, previous *capacityCounterPlan, rows []flowstore.CounterRow) (capacityCounterPlan, error) {
	none := capacityCounterPlan{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("current capacity tenant is inactive")
	}
	var plan capacityCounterPlan
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, principal, permFlowRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
			return err
		}
		period := flow.CapacityBillingPeriod{From: parameters.from, To: parameters.to, Timezone: "UTC", BoundaryPolicy: "explicit_training_window"}
		plan, err = s.capacityCounterPlanInScope(ctx, sc, principal, parameters.target, period, parameters.counter, budget, permFlowRead)
		if err != nil {
			return err
		}
		if previous != nil && !sameCapacityCounterPlan(*previous, plan) {
			return apierror.Unavailable("current forecast source or circuit membership changed; retry")
		}
		return validateCapacityCounterRows(ctx, sc, store.NewDeviceCounterCaptures(s.pool), plan, rows, budget.MemoryBytes/8)
	})
	if err != nil {
		return none, err
	}
	return plan, nil
}
