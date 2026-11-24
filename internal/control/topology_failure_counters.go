// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type topologyFailureCounters struct {
	plan    capacityCounterPlan
	rows    []flowstore.CounterRow
	members []flow.CapacityMeasuredMember
}

// readTopologyFailureCounters reads the complete selected counter population
// through the tenant reader. A denominator requires a stable polled speed
// in the original observations. The capacity measurement model handles
// wraps, gaps and direction on its existing exact five-minute grid.
func (s *Server) readTopologyFailureCounters(ctx context.Context, tenant string, sources topologyFailureSourcePlan, window flow.CapacityMeasurementWindow, budget flowstore.CounterBudget) (topologyFailureCounters, error) {
	none := topologyFailureCounters{}
	bound, present := tenancy.FromContext(ctx)
	if !present || bound.String() != tenant {
		return none, tenancy.ErrNoTenant
	}
	out := topologyFailureCounters{plan: capacityCounterPlan{tenant: tenant, period: flow.CapacityBillingPeriod{From: window.From, To: window.To}}}
	seen := map[string]bool{}
	for _, link := range sources.links {
		target := link.port
		if target.InterfaceID == "" || seen[target.InterfaceID] {
			continue
		}
		if target.Scope.TenantID != tenant {
			return none, tenancy.ErrNoTenant
		}
		seen[target.InterfaceID] = true
		out.plan.members = append(out.plan.members, capacityBillMemberPlan{target: target})
	}
	history, available := flowstore.CounterHistoryOf(s.flowStore)
	if len(out.plan.members) == 0 || !available {
		return out, ctx.Err()
	}
	query, err := capacityBillCounterQuery(out.plan, capacityBillParameters{gap: window.MaximumPollGap}, budget)
	if err != nil {
		return none, err
	}
	// A closed interval can end between polls. Read its witnessed right
	// bracket within the same gap bound, without admitting future samples.
	query.To = window.To.Add(min(window.MaximumPollGap, max(0, time.Since(window.To))))
	out.rows, err = history.CounterPoints(ctx, query)
	if err != nil {
		return none, err
	}
	if err := capacityBillRowsInWindow(out.rows, query); err != nil {
		return none, err
	}
	if err := s.recheckTopologyFailureCounters(ctx, out, budget.MemoryBytes); err != nil {
		return none, err
	}
	speeds := topologyFailureCounterSpeeds(out.rows)
	for i := range out.plan.members {
		member := &out.plan.members[i]
		speed := speeds[capacityBillSource(member.target.Source, member.target.IfIndex)]
		member.maximum = speed
	}
	out.members, err = measureCapacityBillMembers(ctx, out.plan, out.rows, window, budget.MemoryBytes)
	if err != nil {
		return none, err
	}
	return out, ctx.Err()
}

func topologyFailureCounterSpeeds(rows []flowstore.CounterRow) map[capacityBillSourceKey]uint64 {
	speeds := map[capacityBillSourceKey]uint64{}
	for _, row := range rows {
		key := capacityBillSource(row.CounterSource, row.IfIndex)
		old, seen := speeds[key]
		if !row.InterfaceSpeedKnown || seen && old != row.InterfaceSpeedBPS {
			speeds[key] = 0
			continue
		}
		speeds[key] = row.InterfaceSpeedBPS
	}
	return speeds
}

func (s *Server) recheckTopologyFailureCounters(ctx context.Context, evidence topologyFailureCounters, memory int64) error {
	if len(evidence.plan.members) == 0 {
		return ctx.Err()
	}
	// Recheck full membership and receipts together so the two directions
	// cannot cover the same window using different interface incarnations.
	reader := store.NewDeviceCounterCaptures(s.pool)
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != evidence.plan.tenant {
			return tenancy.ErrNoTenant
		}
		for _, member := range evidence.plan.members {
			old := member.target
			current, err := reader.CurrentInterfaceInScope(ctx, sc, old.Scope, old.InterfaceID)
			if err != nil {
				return err
			}
			if !sameCapacityCounterInterface(old, current) {
				return apierror.Unavailable("traffic failure interface authority changed; retry")
			}
		}
		return validateCapacityCounterRows(ctx, sc, reader, evidence.plan, evidence.rows, memory)
	})
}
