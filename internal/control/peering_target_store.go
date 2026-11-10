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
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// loadPeeringTarget reads current user/credential grants and the canonical
// interface under the application's tenant RLS snapshot before consulting
// shared public data. The returned candidate grants no query/publication access.
func (s *Server) loadPeeringTarget(ctx context.Context, actor *auth.Principal, target peeringTarget, budget interfaceRoleBudget) (peeringTargetEligibility, error) {
	none := peeringTargetEligibility{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if target.Scope.TenantID != actor.TenantID {
		return none, apierror.Forbidden("peering target belongs to another tenant")
	}
	if s.pool == nil || budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 {
		return none, apierror.Unavailable("current peering source storage or admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("current peering tenant is inactive")
	}
	var result peeringTargetEligibility
	var prefixes opendata.IXPrefixSnapshot
	var members opendata.IXMembershipSnapshot
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorizeNativeFlow(ctx, principal); err != nil {
			return err
		}
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, target.Scope.ContextID)
		if err != nil {
			return err
		}
		allowed, err := s.flowRoleContextAllowed(ctx, principal, record)
		if err != nil {
			return err
		}
		if !allowed {
			return apierror.Forbidden("current peering context and source-plane access is required")
		}
		input, err := store.NewInterfaceRoleInputs(s.pool).LoadInScope(ctx, sc, target.Scope, target.InterfaceID, entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.WorkUnits / 8})
		if err != nil {
			return err
		}
		prefixes = s.openDataEnricher.IXPrefixes(input.AsOf)
		members = s.openDataEnricher.IXMemberships(input.AsOf)
		result, err = evaluatePeeringTarget(ctx, target, input, prefixes, members, budget)
		return err
	})
	if err != nil {
		return none, err
	}
	at := time.Now().UTC()
	if !prefixes.SameGeneration(s.openDataEnricher.IXPrefixes(at)) || !members.SameGeneration(s.openDataEnricher.IXMemberships(at)) {
		return none, apierror.Unavailable("peering public inputs changed; run a fresh estimate")
	}
	return result, nil
}

func (s *Server) recheckPeeringTarget(ctx context.Context, actor *auth.Principal, previous peeringTargetEligibility, budget interfaceRoleBudget) (peeringTargetEligibility, error) {
	current, err := s.loadPeeringTarget(ctx, actor, previous.Target, budget)
	if err != nil {
		return peeringTargetEligibility{}, err
	}
	if !previous.Eligible || !current.Eligible || current.InputDigest != previous.InputDigest || current.Target != previous.Target || current.RouterID != previous.RouterID || current.PrefixVersion != previous.PrefixVersion || current.MemberVersion != previous.MemberVersion {
		return peeringTargetEligibility{}, apierror.Unavailable("current peering ownership, role or IX evidence changed; run a fresh estimate")
	}
	return current, nil
}
