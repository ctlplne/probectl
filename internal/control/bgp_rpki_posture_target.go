// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/netip"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type bgpRPKIPostureTarget struct {
	Context entity.ContextRecord
	Prefix  entity.Record
	Monitor store.BGPVisibilityMonitor
}

// readBGPRPKIPostureTarget requires an inventory prefix matching the monitored
// network exactly. The caller supplies the current principal from this same
// tenant snapshot before it reads any retained path or validator result.
func (s *Server) readBGPRPKIPostureTarget(ctx context.Context, sc tenancy.Scope, actor *auth.Principal,
	contextID, prefixID, monitorID string) (bgpRPKIPostureTarget, error) {
	var empty bgpRPKIPostureTarget
	tenant, present := tenancy.FromContext(ctx)
	if !present || sc.Tenant != tenant || actor == nil || actor.TenantID != tenant.String() || sc.Q == nil {
		return empty, tenancy.ErrNoTenant
	}
	registry := store.NewEntityRegistry(s.pool)
	owned, err := registry.GetEntityContextInScope(ctx, sc, contextID)
	if err != nil {
		return empty, err
	}
	resource := entityContextResource(owned)
	resource["entity_id"], resource["monitor_id"] = prefixID, monitorID
	if err := s.authorize(ctx, actor, ai.PermEntitiesRead, auth.RBACGlobal, resource); err != nil {
		return empty, err
	}
	scope := entity.Scope{TenantID: tenant.String(), ContextID: owned.ContextID}
	prefix, err := registry.GetEntityInScope(ctx, sc, scope, prefixID)
	if err != nil {
		return empty, err
	}
	monitor, err := store.BGPVisibilityMonitorInScope(ctx, sc, monitorID)
	if err != nil {
		return empty, err
	}
	network, err := netip.ParsePrefix(prefix.NetworkPrefix)
	if err != nil || prefix.Kind != entity.Prefix || network != monitor.Prefix {
		return empty, apierror.NotFound("owned prefix and selected monitor do not match")
	}
	resource["prefix"] = network.String()
	for _, permission := range []string{ai.PermEntitiesRead, ai.PermEventsRead} {
		if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
			return empty, err
		}
	}
	return bgpRPKIPostureTarget{Context: owned, Prefix: prefix, Monitor: monitor}, ctx.Err()
}
