// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleInterfaceRoleExplanation(w http.ResponseWriter, r *http.Request) error {
	body, err := s.interfaceRoleExplanation(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

func (s *Server) interfaceRoleExplanation(r *http.Request) (json.RawMessage, error) {
	r, budget, done, err := s.beginInterfaceRoleOperation(r)
	if err != nil {
		return nil, err
	}
	defer done()
	// Two complete input snapshots share the captured deadline/fairness slot.
	// Reserve the other half for association, evaluation and encoding.
	readBudget := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.MemoryBytes / 8}
	before, err := s.readAuthorizedInterfaceRoleInputs(r, readBudget)
	if err != nil {
		return nil, interfaceRoleAPIError(err)
	}
	result, err := explainInterfaceRoleInputs(r.Context(), before, nil,
		interfaceRoleBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.MemoryBytes / 4})
	if err != nil {
		return nil, interfaceRoleAPIError(err)
	}
	// Refresh actual user grants, credential ceiling, context ABAC, lifecycle
	// and EVERY source/configuration fact after computation. Neither a cached
	// principal nor only the winning evidence authorizes publication.
	after, err := s.readAuthorizedInterfaceRoleInputs(r, readBudget)
	if err != nil {
		return nil, interfaceRoleAPIError(err)
	}
	if !sameInterfaceRoleInputs(before, after) {
		return nil, apierror.Unavailable("interface role inputs changed; retry")
	}
	now := time.Now().UTC()
	if before.SNMP != nil && (!roleInputClock(before.SNMP.InterfaceRoleEvidenceClock).current(now) ||
		before.SNMP.Prefixes != nil && !roleInputClock(before.SNMP.PrefixClock).current(now)) {
		return nil, apierror.Unavailable("interface role evidence expired; retry")
	}
	if before.SNMP != nil {
		for _, binding := range before.SNMP.Bindings {
			if !roleInputClock(binding.InterfaceRoleEvidenceClock).current(now) {
				return nil, apierror.Unavailable("interface role binding expired; retry")
			}
		}
	}
	for _, peer := range before.Peers {
		if !roleInputClock(peer.InterfaceRoleEvidenceClock).current(now) {
			return nil, apierror.Unavailable("interface role evidence expired; retry")
		}
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	return interfaceRolePublication(result, budget)
}

func (s *Server) readAuthorizedInterfaceRoleInputs(r *http.Request, budget entity.InterfaceRolePolicyBudget) (store.InterfaceRoleInputs, error) {
	none := store.InterfaceRoleInputs{}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return none, apierror.Forbidden("current tenant user is required")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(r.Context(), actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("current tenant is inactive")
	}
	scope, err := (entity.Scope{TenantID: actor.TenantID, ContextID: r.PathValue("context_id")}).Normalize()
	if err != nil {
		return none, err
	}
	var out store.InterfaceRoleInputs
	err = tenancy.InTenantReadSnapshot(r.Context(), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, scope.ContextID)
		if err != nil {
			return err
		}
		for _, permission := range []string{ai.PermEntitiesRead, entitySourcePermission(entity.DeviceTarget), entitySourcePermission(entity.BMPPeer)} {
			if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
				return err
			}
		}
		out, err = store.NewInterfaceRoleInputs(s.pool).LoadInScope(ctx, sc, scope, r.PathValue("id"), budget)
		return err
	})
	if err != nil {
		return none, err
	}
	return out, nil
}
