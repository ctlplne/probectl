// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// One callback belongs to one current-user/RLS snapshot. Context records can
// share decode memory, while every source/router/prefix still receives its own
// RBAC/ABAC decision. There is no cross-request or cross-tenant permission cache.
func (s *Server) routingChangeAuthorizer(actor *auth.Principal, permissions ...string) store.RoutingChangeAuthorizer {
	contexts := map[string]entity.ContextRecord{}
	return func(ctx context.Context, sc tenancy.Scope, source store.BGPRoutingSource, event change.Event) error {
		if actor == nil || actor.TenantID != sc.Tenant.String() || source.TenantID != actor.TenantID || event.TenantID != actor.TenantID || event.Routing == nil {
			return entity.ErrScopeMismatch
		}
		for index, target := range [][2]string{{source.ContextID, source.RouterID}, {event.Routing.BaseContextID, event.Routing.BaseRouterID}} {
			if index == 1 && target == [2]string{source.ContextID, source.RouterID} {
				continue
			}
			record, ok := contexts[target[0]]
			if !ok {
				var err error
				record, err = store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, target[0])
				if err != nil {
					return err
				}
				contexts[target[0]] = record
			}
			resource := entityContextResource(record)
			resource["entity_id"], resource["agent_id"], resource["source_kind"], resource["source_ref"], resource["prefix"] = target[1], source.CollectorAgentID, string(entity.BMPPeer), source.SourceRef, event.Prefix
			for _, permission := range append([]string{ai.PermEventsRead, ai.PermEntitiesRead}, permissions...) {
				if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
					return err
				}
			}
		}
		return ctx.Err()
	}
}
