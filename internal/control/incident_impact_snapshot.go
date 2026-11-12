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

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type incidentImpactSnapshot struct {
	authority                   *currentUserAuthority
	inputs                      *store.IncidentImpactInputs
	sources                     []store.IncidentImpactSource
	owners                      []store.CapturedFlowOwner
	sourceDigest, captureDigest string
}

// Deterministic impact reads have their own source permissions. They never
// acquire AI or routing-analysis authority as a side effect of incident.read.
func (s *Server) authorizeIncidentImpact(ctx context.Context, actor *auth.Principal, resource map[string]string) error {
	for _, permission := range []string{permIncidentRead, permFlowRead, "entities.read", "metrics.read", "events.read"} {
		if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *Server) loadIncidentImpactSnapshot(ctx context.Context, actor *auth.Principal, id string, reads []flowstore.RoutingCaptureRead, budget flowstore.ExplorerBudget) (incidentImpactSnapshot, error) {
	none := incidentImpactSnapshot{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if s.pool == nil || budget.Validate() != nil {
		return none, apierror.Unavailable("incident impact source storage or admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("incident impact tenant is inactive")
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	var result incidentImpactSnapshot
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		resource := map[string]string{auth.ResourceTenantKey: actor.TenantID, "incident_id": id}
		if err := s.authorizeIncidentImpact(ctx, principal, resource); err != nil {
			return err
		}
		limit := budget.MemoryBytes / 4
		inputs, err := (store.Incidents{}).ImpactInputs(ctx, sc, id, limit)
		if err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity) error {
			if record.TenantID != principal.TenantID || record.ContextID != member.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			resource["incident_id"], resource["entity_id"] = id, member.EntityID
			return s.authorizeIncidentImpact(ctx, principal, resource)
		}
		sources, err := (store.Incidents{}).ImpactSourcesInScope(ctx, sc, inputs,
			entity.InterfaceRolePolicyBudget{MemoryBytes: limit, WorkUnits: limit}, authorize)
		if err != nil {
			return err
		}
		digest, err := hashFlowRoleInputs(ctx, nil, inputs, limit)
		if err != nil {
			return err
		}
		digest, err = hashFlowRoleInputs(ctx, digest, sources, limit)
		if err != nil {
			return err
		}
		result = incidentImpactSnapshot{authority: current, inputs: inputs, sources: sources, sourceDigest: hex.EncodeToString(digest)}
		if len(reads) == 0 {
			return nil
		}
		// Only server-selected incident sources can authorize an original
		// receipt. A raw row cannot introduce another context/router.
		authorizeOwner := func(ctx context.Context, record entity.ContextRecord, binding store.InterfaceRoleFlowBinding) error {
			for _, source := range sources {
				if source.Member.ContextID != record.ContextID {
					continue
				}
				for _, selected := range source.Selections {
					if selected.AgentID == binding.AgentID && selected.Exporter == binding.Exporter && selected.Protocol == binding.Protocol && selected.Domain == binding.Domain {
						return authorize(ctx, record, source.Member)
					}
				}
			}
			return entity.ErrScopeMismatch
		}
		owners, err := (store.CapturedFlowOwners{}).ReadInScope(ctx, sc, reads,
			store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.MemoryBytes / 2, StateBytes: budget.MemoryBytes / 2}, authorizeOwner)
		if err != nil {
			return err
		}
		digest, err = hashFlowRoleInputs(ctx, nil, owners, limit)
		if err != nil {
			return err
		}
		result.owners, result.captureDigest = owners, hex.EncodeToString(digest)
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrIncidentImpactBudget) {
			return none, flowExplorerStoreError(flowstore.ErrExplorerBudget)
		}
		return none, flowRoutingQueryError(err)
	}
	return result, nil
}
