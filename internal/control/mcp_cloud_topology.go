// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func (s *Server) nativeCloudTopology(ctx context.Context, actor *auth.Principal, at time.Time) (topology.Viz, error) {
	if actor == nil || actor.UserID == "" || actor.TenantID == "" {
		return topology.Viz{}, apierror.Unauthorized("current tenant user is required")
	}
	if bound, present := tenancy.FromContext(ctx); present && bound.String() != actor.TenantID {
		return topology.Viz{}, apierror.Forbidden("cloud inventory tenant scope does not match the credential")
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return topology.Viz{}, err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	if err := s.authorize(ctx, actor, ai.PermTopologyRead, auth.RBACGlobal, nil); err != nil {
		return topology.Viz{}, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return topology.Viz{}, apierror.Unavailable("cloud inventory query admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	view := topology.ToViz(topology.Snapshot{Tenant: actor.TenantID, At: at.UTC()})
	if err := s.projectCloudTopology(ctx, actor.TenantID, view.At, &view); err != nil {
		return topology.Viz{}, err
	}
	return view, ctx.Err()
}
