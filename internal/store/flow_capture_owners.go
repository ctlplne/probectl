// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CapturedFlowOwner describes only the original flow's canonical measurement
// point. Routing facts confer no authority and are never returned by this read.
type CapturedFlowOwner struct {
	Reference         entity.FlowCaptureReference
	Available         bool
	Owner             InterfaceRoleFlowBinding
	CurrentSourceID   string
	CurrentOwnerSince time.Time
}

// CapturedFlowOwners reuses the existing immutable capture/erasure store. It
// neither reads today's RIB nor requires access to routing-analysis fields.
type CapturedFlowOwners struct{}

type capturedFlowOwnerCurrent struct {
	binding InterfaceRoleFlowBinding
	since   time.Time
	valid   bool
}

type capturedFlowOwnerKey struct {
	context, agent, router, exporter, protocol string
	domain                                     uint32
}

type capturedFlowOwnerRead struct {
	budget     BGPRoutingBudget
	owners     []InterfaceRoleExporterOwner
	bindings   map[string][]InterfaceRoleFlowBinding
	current    map[capturedFlowOwnerKey]capturedFlowOwnerCurrent
	objects    map[[64]byte]BGPRoutingFlowLookup
	authorized map[capturedFlowOwnerKey]bool
}

// ReadInScope requires an existing repeatable tenant snapshot and a current
// actor authorizer. Every original key/clock/tuple is checked, even when flows
// share immutable objects. No cache or source authority survives the request.
func (CapturedFlowOwners) ReadInScope(ctx context.Context, sc tenancy.Scope, reads []flowstore.RoutingCaptureRead, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord, InterfaceRoleFlowBinding) error) ([]CapturedFlowOwner, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return nil, err
	}
	if authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	keys, err := routingQueryCaptureKeys(ctx, sc, reads, &budget)
	if err != nil {
		return nil, err
	}
	headers, err := loadRoutingQueryCaptureHeaders(ctx, sc, keys)
	if err != nil {
		return nil, err
	}
	hints, err := loadCapturedFlowOwnerHints(ctx, sc, keys)
	if err != nil {
		return nil, err
	}
	state := capturedFlowOwnerRead{budget: budget, bindings: map[string][]InterfaceRoleFlowBinding{}, current: map[capturedFlowOwnerKey]capturedFlowOwnerCurrent{},
		objects: map[[64]byte]BGPRoutingFlowLookup{}, authorized: map[capturedFlowOwnerKey]bool{}}
	// Check each canonical context before reading/admitting content objects.
	for _, read := range reads {
		header, found := headers[read.Ref.Key]
		if !found || header.clock != read.Ref.CapturedAt.UnixNano() {
			continue
		}
		hint, found := hints[read.Ref.Key]
		if !found || hint.agent != read.Sender {
			return nil, errRoutingCaptureFormat
		}
		key := capturedFlowOwnerKey{header.contextID, hint.agent, hint.router, read.Witness.Input.Exporter.String(), read.Witness.Input.Protocol, read.Witness.Input.Domain}
		if state.authorized[key] {
			continue
		}
		record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, header.contextID)
		if err != nil {
			return nil, err
		}
		selector := InterfaceRoleFlowBinding{Scope: entity.Scope{TenantID: record.TenantID, ContextID: record.ContextID}, AgentID: hint.agent, RouterID: hint.router,
			Exporter: read.Witness.Input.Exporter, Protocol: read.Witness.Input.Protocol, Domain: read.Witness.Input.Domain}
		if err := authorize(ctx, record, selector); err != nil {
			return nil, err
		}
		state.authorized[key] = true
	}
	if len(state.authorized) == 0 {
		out := make([]CapturedFlowOwner, len(reads))
		for i, read := range reads {
			out[i].Reference = read.Ref
		}
		return out, ctx.Err()
	}
	var generation int64
	var invalidating bool
	if err := sc.Q.QueryRow(ctx, `SELECT generation,invalidating OR observation_erasing FROM flow_snapshot_epochs WHERE tenant_id=$1`, sc.Tenant.String()).Scan(&generation, &invalidating); err != nil {
		return nil, err
	}
	if invalidating || generation <= 0 {
		return nil, sourceepoch.ErrInvalidating
	}
	state.owners, err = (&InterfaceRoleInputsStore{}).ExporterOwnersInScope(ctx, sc,
		entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.WorkUnits / 8})
	if err != nil {
		return nil, err
	}
	out := make([]CapturedFlowOwner, len(reads))
	for i, read := range reads {
		out[i].Reference = read.Ref
		header, found := headers[read.Ref.Key]
		if !found || header.clock != read.Ref.CapturedAt.UnixNano() {
			continue // legacy, retired or unavailable; never guessed as healthy zero
		}
		lookup, cached := state.objects[header.objects]
		if !cached {
			receipt, exists, err := readRoutingCaptureInScope(ctx, sc, read.Ref.Key, state.budget)
			if err != nil {
				return nil, err
			}
			if !exists || receipt.objects == nil || !receipt.capturedAt.Equal(read.Ref.CapturedAt) {
				continue
			}
			lookup, err = decodeRoutingCapture(ctx, *receipt.objects, state.budget)
			if err != nil {
				return nil, err
			}
			if err := routingBatchCharge(&state.budget, int64(len(receipt.objects.facts.payload)+len(receipt.objects.clocks.payload))*8+4096, 256); err != nil {
				return nil, err
			}
			state.objects[header.objects] = lookup
		}
		owner := lookup.Owner
		hint := hints[read.Ref.Key]
		if owner.TenantID != sc.Tenant.String() || owner.AgentID != hint.agent || owner.RouterID != hint.router || !capturedFlowOwnerMatches(owner, read, header) {
			return nil, errRoutingCaptureFormat
		}
		current, err := state.continuousOwner(ctx, sc, owner, read.Witness.Input)
		if err != nil {
			return nil, err
		}
		if current.valid && !read.Ref.CapturedAt.Before(current.since) {
			out[i].Available, out[i].Owner, out[i].CurrentSourceID = true, owner, current.binding.SourceID
			out[i].CurrentOwnerSince = current.since
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func capturedFlowOwnerMatches(owner InterfaceRoleFlowBinding, read flowstore.RoutingCaptureRead, header routingQueryCaptureHeader) bool {
	input, at := read.Witness.Input, read.Ref.CapturedAt
	return owner.ContextID == header.contextID && owner.AgentID == read.Sender && owner.Exporter == input.Exporter.Unmap() &&
		owner.Protocol == input.Protocol && owner.Domain == input.Domain && !owner.ObservedAt.After(at) && owner.ValidUntil.After(at)
}

func (state *capturedFlowOwnerRead) continuousOwner(ctx context.Context, sc tenancy.Scope, captured InterfaceRoleFlowBinding, input entity.FlowCaptureInput) (capturedFlowOwnerCurrent, error) {
	key := capturedFlowOwnerKey{captured.ContextID, captured.AgentID, captured.RouterID, captured.Exporter.String(), captured.Protocol, captured.Domain}
	if value, found := state.current[key]; found {
		return value, nil
	}
	none := capturedFlowOwnerCurrent{}
	state.current[key] = none // unavailable results share only this request's snapshot
	owner, err := routingFlowOwner(sc.Tenant.String(), input.Exporter.Unmap(), state.owners)
	if errors.Is(err, ErrBGPRoutingFlowSource) {
		return none, nil
	}
	if err != nil {
		return none, err
	}
	if owner.AgentID != captured.AgentID || owner.Scope != captured.Scope || owner.RouterID != captured.RouterID {
		return none, nil
	}
	bindings, found := state.bindings[owner.ContextID]
	if !found {
		bindings, err = (&InterfaceRoleInputsStore{}).FlowBindingsInScope(ctx, sc, owner.Scope,
			entity.InterfaceRolePolicyBudget{MemoryBytes: state.budget.MemoryBytes / 8, WorkUnits: state.budget.WorkUnits / 8})
		if err != nil {
			return none, err
		}
		if err := routingBatchCharge(&state.budget, int64(len(bindings))*4096, int64(len(bindings))*256); err != nil {
			return none, err
		}
		state.bindings[owner.ContextID] = bindings
	}
	binding, err := routingFlowBinding(owner, input, bindings)
	if errors.Is(err, ErrBGPRoutingFlowSource) {
		return none, nil
	}
	if err != nil {
		return none, err
	}
	// Refreshing an observation/certificate does not erase traffic history.
	// Reassignment or deletion/recreation must not revive an old association.
	var since time.Time
	err = sc.Q.QueryRow(ctx, `SELECT GREATEST(source.assigned_at,assignment.assigned_at,node.created_at)
		FROM entity_source_contexts source JOIN entity_agent_contexts assignment
		ON (assignment.tenant_id,assignment.context_id,assignment.agent_id)=(source.tenant_id,source.context_id,source.agent_id)
		JOIN entities node ON (node.tenant_id,node.context_id,node.id)=(source.tenant_id,source.context_id,source.anchor_entity_id)
		WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.agent_id=$3
		AND source.source_kind='flow_exporter' AND source.source_ref=$4 AND node.id=$5 AND node.kind='device'`,
		sc.Tenant.String(), owner.ContextID, owner.AgentID, owner.Exporter.String(), owner.RouterID).Scan(&since)
	if err != nil {
		return none, err
	}
	value := capturedFlowOwnerCurrent{binding: binding, since: since, valid: true}
	state.current[key] = value
	return value, nil
}
