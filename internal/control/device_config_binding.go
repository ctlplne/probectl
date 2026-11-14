// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
)

func (s *Server) authorizeConfigArchiveBinding(r *http.Request, binding *device.ConfigArchiveBinding, permission string) error {
	actor := auth.PrincipalFrom(r.Context())
	if binding == nil || s.pool == nil || actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return apierror.Forbidden("a current tenant user is required for a canonical archive binding")
	}
	boundCtx, err := bindFlowRoleContext(r.Context(), actor)
	if err != nil {
		return err
	}
	r = r.WithContext(boundCtx)
	resource, err := s.entityResource(r.Context(), entity.Scope{TenantID: actor.TenantID, ContextID: binding.ContextID})
	if err != nil {
		return err
	}
	resource["entity_id"], resource["agent_id"], resource["source_kind"], resource["source_ref"] = binding.DeviceEntityID, binding.AgentID, string(entity.DeviceTarget), binding.SourceRef
	current, err := loadCurrentUserAuthority(r.Context(), s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(r.Context(), actor)
	if err != nil {
		return err
	}
	for _, required := range []string{permission, ai.PermEntitiesRead} {
		if err := s.authorize(ctx, principal, required, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	credential := s.resolvePrincipal(r)
	if credential == nil {
		return unauthenticated(r)
	}
	if !auth.SamePrincipalAuthority(actor, credential) {
		return apierror.Forbidden("configuration archive credential authority changed")
	}
	return r.Context().Err()
}
