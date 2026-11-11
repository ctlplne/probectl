// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type capacityBillSourceKey struct {
	context, device, agent, ref string
	sourceAt, agentAt           int64
	index                       uint32
}

func capacityBillSource(source flowstore.CounterSource, index uint32) capacityBillSourceKey {
	return capacityBillSourceKey{source.ContextID, source.DeviceID, source.AgentID, source.SourceRef, source.SourceAssignedAt.UnixNano(), source.AgentAssignedAt.UnixNano(), index}
}

func capacityBillCounterQuery(plan capacityCounterPlan, parameters capacityBillParameters, budget flowstore.CounterBudget) (flowstore.CounterQuery, error) {
	from := plan.period.From.Add(-parameters.gap)
	if !from.Before(plan.period.From) || from.UnixNano() <= 0 || !time.Unix(0, from.UnixNano()).Equal(from) {
		return flowstore.CounterQuery{}, flowstore.ErrCounterHistoryInput
	}
	query := flowstore.CounterQuery{TenantID: plan.tenant, From: from, To: plan.period.To, Budget: budget}
	groups := map[capacityBillSourceKey]int{}
	for _, member := range plan.members {
		key := capacityBillSource(member.target.Source, 0)
		if group, present := groups[key]; present {
			query.Sources[group].IfIndexes = append(query.Sources[group].IfIndexes, member.target.IfIndex)
		} else {
			groups[key] = len(query.Sources)
			query.Sources = append(query.Sources, flowstore.CounterSelector{CounterSource: member.target.Source, IfIndexes: []uint32{member.target.IfIndex}})
		}
	}
	return query, nil
}

func validateCapacityCounterRows(ctx context.Context, sc tenancy.Scope, reader *store.DeviceCounterCaptures, plan capacityCounterPlan, rows []flowstore.CounterRow, memoryBytes int64) error {
	if memoryBytes <= 0 || int64(len(plan.members)) > memoryBytes/4096 {
		return flowstore.ErrCounterHistoryBudget
	}
	selected := make(map[capacityBillSourceKey]bool, len(plan.members))
	for _, member := range plan.members {
		key := capacityBillSource(member.target.Source, member.target.IfIndex)
		if selected[key] {
			return flowstore.ErrCounterHistoryInput
		}
		selected[key] = true
	}
	keys := [][32]byte{}
	seen := map[[32]byte]bool{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if row.TenantID != sc.Tenant.String() || !selected[capacityBillSource(row.CounterSource, row.IfIndex)] || row.Width != 32 && row.Width != 64 {
			return entity.ErrScopeMismatch
		}
		key, err := entity.CounterCaptureKey(row.TenantID, row.AgentID, row.RawDigest, entity.CounterCaptureInput{ConfiguredTarget: row.SourceRef,
			PollStartedAt: row.PollStartedAt, PollCompletedAt: row.PollCompletedAt, PointCount: row.Population})
		if err != nil || key != row.CaptureKey {
			return flowstore.ErrCounterHistoryInput
		}
		if !seen[key] {
			if int64(len(keys))+1 > (memoryBytes-4096)/8192 {
				return flowstore.ErrCounterHistoryBudget
			}
			seen[key] = true
			keys = append(keys, key)
		}
	}
	witnesses, err := reader.LookupWitnessesInScope(ctx, sc, keys, memoryBytes/2)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		witness, found := witnesses[row.CaptureKey]
		if !found || witness.Scope.TenantID != row.TenantID || witness.Scope.ContextID != row.ContextID || witness.DeviceID != row.DeviceID || witness.SenderSerial != row.SenderSerial ||
			!witness.CapturedAt.Equal(row.CapturedAt) || !witness.SourceAssignedAt.Equal(row.SourceAssignedAt) || !witness.AgentAssignedAt.Equal(row.AgentAssignedAt) {
			return store.ErrCounterCaptureUnavailable
		}
	}
	return nil
}
