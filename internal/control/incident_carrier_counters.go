// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (s *Server) loadCarrierCounters(ctx context.Context, actor *auth.Principal, snapshot incidentVerdictSnapshot, result *incident.CarrierPack, budget flowstore.ExplorerBudget) ([]incidentCarrierCounterCheck, error) {
	remaining := budget.MemoryBytes / 6
	checks := []incidentCarrierCounterCheck{}
	history, available := flowstore.CounterHistoryOf(s.flowStore)
	for _, item := range snapshot.evidence.interfaces {
		if !item.source.Current || !item.direct && !item.incidentRouter {
			continue
		}
		switch string(item.role.Role) {
		case string(entity.InterfaceRoleTransit), string(entity.InterfaceRoleIX), string(entity.InterfaceRolePrivate):
		default:
			continue
		}
		if remaining < 8192 {
			return nil, store.ErrIncidentImpactBudget
		}
		source := item.source
		handoff := incident.CarrierHandoff{ContextID: source.ContextID, RouterID: source.RouterID, InterfaceID: source.EntityID, AgentID: source.AgentID, SourceRef: source.ConfiguredRef, IfIndex: source.IfIndex, CurrentRole: string(item.role.Role), RoleEvaluatedAt: item.role.AsOf, Coverage: "counter_history_unavailable", Counters: []incident.CarrierCounterObservation{}}
		if !available {
			result.Handoffs = append(result.Handoffs, handoff)
			continue
		}
		counterBudget := flowstore.CounterBudget{MemoryBytes: remaining / 2, WorkUnits: remaining / 2, Timeout: budget.ExecutionLimit}
		selected := capacityCounterSelection{Scope: entity.Scope{TenantID: actor.TenantID, ContextID: source.ContextID}, InterfaceID: source.EntityID}
		target, err := s.capacityCounterSnapshot(ctx, actor, selected, nil, nil, counterBudget)
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrCounterCaptureUnavailable) {
			handoff.Coverage = "no_current_counter_source"
			result.Handoffs = append(result.Handoffs, handoff)
			continue
		}
		if err != nil {
			return nil, err
		}
		if target.Source.DeviceID != source.RouterID || target.Source.AgentID != source.AgentID || target.Source.SourceRef != source.ConfiguredRef || target.IfIndex != source.IfIndex {
			return nil, entity.ErrScopeMismatch
		}
		rows, err := history.CounterPoints(ctx, flowstore.CounterQuery{TenantID: actor.TenantID, From: result.From, To: result.To, Sources: []flowstore.CounterSelector{{CounterSource: target.Source, IfIndexes: []uint32{target.IfIndex}}}, Budget: counterBudget})
		if err != nil {
			return nil, err
		}
		if _, err := s.capacityCounterSnapshot(ctx, actor, selected, &target, rows, counterBudget); err != nil {
			return nil, err
		}
		// Keep every selected metric, exact value and receipt. Rates and resets
		// are not inferred from a missing predecessor or a rounded float series.
		if int64(len(rows)) > remaining/8192 {
			return nil, store.ErrIncidentImpactBudget
		}
		remaining -= 8192 * int64(len(rows))
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if row.PollStartedAt.Before(result.From) || !row.PollStartedAt.Before(result.To) {
				return nil, flowstore.ErrCounterHistoryInput
			}
			observation := incident.CarrierCounterObservation{Metric: row.Name, Value: strconv.FormatUint(row.Value, 10), Width: int(row.Width), PollStartedAt: row.PollStartedAt, PollCompletedAt: row.PollCompletedAt, CaptureKey: hex.EncodeToString(row.CaptureKey[:]), CaptureDigest: hex.EncodeToString(row.RawDigest[:]), UptimeKnown: row.UptimeKnown, DiscontinuityKnown: row.DiscontinuityKnown}
			if row.UptimeKnown {
				observation.UptimeTicks = strconv.FormatUint(uint64(row.UptimeTicks), 10)
			}
			if row.DiscontinuityKnown {
				observation.DiscontinuityTicks = strconv.FormatUint(uint64(row.DiscontinuityTicks), 10)
			}
			handoff.Counters = append(handoff.Counters, observation)
		}
		remaining -= 8192
		handoff.Coverage = "no_retained_counter_polls"
		if len(handoff.Counters) > 0 {
			handoff.Coverage = "observed_original_counter_polls"
			result.Coverage.Handoffs = "observed_original_counter_polls"
		}
		result.Handoffs = append(result.Handoffs, handoff)
		checks = append(checks, incidentCarrierCounterCheck{selected: selected, target: target, rows: rows, budget: counterBudget})
	}
	if len(result.Handoffs) == 0 {
		result.Coverage.Missing = append(result.Coverage.Missing, "current_authorized_carrier_handoff")
	}
	return checks, ctx.Err()
}
