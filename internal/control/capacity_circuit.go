// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) loadCapacityCircuit(ctx context.Context, actor *auth.Principal, tagID, value string, memoryBytes int64) (store.CapacityCircuitSnapshot, error) {
	none := store.CapacityCircuitSnapshot{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if s.pool == nil || memoryBytes <= 0 {
		return none, apierror.Unavailable("capacity circuit storage or admission is unavailable")
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
	var out store.CapacityCircuitSnapshot
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, principal, permTagsRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord) error {
			if record.TenantID != actor.TenantID {
				return entity.ErrScopeMismatch
			}
			for _, permission := range []string{permTagsRead, ai.PermEntitiesRead, ai.PermMetricsRead} {
				if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
					return err
				}
			}
			return nil
		}
		out, err = store.NewTagSnapshots(s.pool).CapacityCircuitInScope(ctx, sc, tagID, value, memoryBytes, authorize)
		return err
	})
	if err != nil {
		return none, err
	}
	return out, nil
}

func (s *Server) recheckCapacityCircuit(ctx context.Context, actor *auth.Principal, before store.CapacityCircuitSnapshot, memoryBytes int64) error {
	after, err := s.loadCapacityCircuit(ctx, actor, before.TagID, before.Value, memoryBytes)
	if err != nil {
		return err
	}
	if before.TenantID != after.TenantID || before.Revision != after.Revision || !slices.Equal(before.Members, after.Members) {
		return apierror.Unavailable("capacity circuit membership changed; retry")
	}
	return nil
}
