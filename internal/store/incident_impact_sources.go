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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// IncidentImpactSource links a persisted incident member to current, attested
// measurement points. Selectors do not authorize raw rows: their original
// captured owners must also agree before an observation can be attributed.
type IncidentImpactSource struct {
	Member             IncidentImpactEntity
	Kind               entity.Kind
	Reason             string
	Selections         []flowstore.IncidentTrafficSource
	Evidence           []string
	ValidUntil         time.Time
	InterfaceNotBefore time.Time
}

// ImpactSourcesInScope authorizes each canonical member before reading its
// current source metadata. Tenant-wide exporter uniqueness includes unreadable
// and unobserved competitors. Empty coverage never means zero traffic.
func (Incidents) ImpactSourcesInScope(ctx context.Context, sc tenancy.Scope, inputs *IncidentImpactInputs, budget entity.InterfaceRolePolicyBudget,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) ([]IncidentImpactSource, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || sc.Tenant != bound || inputs == nil || inputs.TenantID != bound.String() || authorize == nil || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	admission := roleInputAdmission{memory: budget.MemoryBytes, work: budget.WorkUnits}
	if err := admission.charge(ctx, 4096+int64(len(inputs.Entities))*1024, int64(len(inputs.Entities))); err != nil {
		return nil, err
	}
	// Denied readers cannot use ownership enumeration/admission to learn
	// another context's metadata population.
	for _, member := range inputs.Entities {
		record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, member.ContextID)
		if err != nil {
			return nil, err
		}
		if err := authorize(ctx, record, member); err != nil {
			return nil, err
		}
	}
	reader := NewInterfaceRoleInputs(nil)
	owners, err := reader.ExporterOwnersInScope(ctx, sc, entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.WorkUnits / 4})
	if err != nil {
		return nil, err
	}
	bindings := map[string][]InterfaceRoleFlowBinding{}
	out := make([]IncidentImpactSource, 0, len(inputs.Entities))
	for _, member := range inputs.Entities {
		if _, err := validRegistryUUID(member.EntityID); err != nil {
			return nil, err
		}
		item := IncidentImpactSource{Member: member, Reason: "unavailable_source", Selections: []flowstore.IncidentTrafficSource{}, Evidence: []string{}}
		var parent string
		err = sc.Q.QueryRow(ctx, `SELECT kind,COALESCE(parent_entity_id::text,'') FROM entities
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, inputs.TenantID, member.ContextID, member.EntityID).Scan(&item.Kind, &parent)
		if errors.Is(err, pgx.ErrNoRows) {
			out = append(out, item)
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := entity.ValidateKind(item.Kind); err != nil {
			return nil, err
		}
		router := member.EntityID
		index := uint32(0)
		if item.Kind == entity.Interface {
			part := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: admission.work}
			facts, err := reader.LoadInScope(ctx, sc, entity.Scope{TenantID: inputs.TenantID, ContextID: member.ContextID}, member.EntityID, part)
			if err != nil {
				return nil, err
			}
			if facts.SNMP == nil || facts.IfIndex == 0 || facts.RouterID == "" || facts.RouterID != parent {
				out = append(out, item)
				continue
			}
			matches := 0
			for _, binding := range facts.SNMP.Bindings {
				if binding.IfIndex == facts.IfIndex {
					matches++
					if binding.InterfaceID != member.EntityID {
						matches++ // A competing canonical identity cannot supply this index.
					}
				}
			}
			if matches != 1 {
				item.Reason = "ambiguous_interface_index"
				out = append(out, item)
				continue
			}
			router, index = facts.RouterID, facts.IfIndex
			// Canonical ifIndex identities cannot be reparented by the registry
			// writer. Their current device-target assignment must also have
			// existed throughout the original observation, not only today.
			if err := sc.Q.QueryRow(ctx, `SELECT GREATEST(node.created_at,source.assigned_at,assignment.assigned_at)
				FROM entities node JOIN entity_source_contexts source ON
				(source.tenant_id,source.context_id,source.agent_id,source.source_kind,source.source_ref)=
				(node.tenant_id,node.context_id,node.source_agent_id,'device_target',node.configured_ref)
				JOIN entity_agent_contexts assignment ON
				(assignment.tenant_id,assignment.context_id,assignment.agent_id)=(source.tenant_id,source.context_id,source.agent_id)
				WHERE node.tenant_id=$1 AND node.context_id=$2 AND node.id=$3 AND node.parent_entity_id=$4
				AND source.anchor_entity_id=$4`, inputs.TenantID, member.ContextID, member.EntityID, router).Scan(&item.InterfaceNotBefore); err != nil {
				return nil, err
			}
			item.Evidence = append(item.Evidence, facts.SNMP.SourceID)
			item.ValidUntil = facts.SNMP.ValidUntil
		} else if item.Kind != entity.Device {
			item.Reason = "not_a_flow_measurement_point"
			out = append(out, item)
			continue
		}
		current, found := bindings[member.ContextID]
		if !found {
			current, err = reader.FlowBindingsInScope(ctx, sc, entity.Scope{TenantID: inputs.TenantID, ContextID: member.ContextID},
				entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: admission.work})
			if err != nil {
				return nil, err
			}
			if err := admission.charge(ctx, int64(len(current))*2048, int64(len(current))); err != nil {
				return nil, err
			}
			bindings[member.ContextID] = current
		}
		for _, binding := range current {
			if err := admission.charge(ctx, 0, 1); err != nil {
				return nil, err
			}
			if binding.RouterID != router {
				continue
			}
			owner, err := routingFlowOwner(inputs.TenantID, binding.Exporter, owners)
			if errors.Is(err, ErrBGPRoutingFlowSource) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if owner.Scope != binding.Scope || owner.AgentID != binding.AgentID || owner.RouterID != router {
				continue
			}
			if err := admission.charge(ctx, 2048+int64(len(binding.AgentID)), 1); err != nil {
				return nil, err
			}
			selector := flowstore.IncidentTrafficSource{AgentID: binding.AgentID, Exporter: binding.Exporter, Protocol: binding.Protocol, Domain: binding.Domain, WholeDevice: index == 0}
			if index != 0 {
				selector.InterfaceIndices = []uint32{index}
			}
			item.Selections = append(item.Selections, selector)
			item.Evidence = append(item.Evidence, binding.SourceID)
			if item.ValidUntil.IsZero() || binding.ValidUntil.Before(item.ValidUntil) {
				item.ValidUntil = binding.ValidUntil
			}
		}
		if len(item.Selections) > 0 {
			item.Reason = "current_attested_source"
		}
		out = append(out, item)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
