// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The caller supplies current user/credential policy from the same tenant
// snapshot as the original source read. Flow access cannot grant BGP access.
func (s *Server) authorizeFlowRoutingContext(ctx context.Context, principal *auth.Principal, record entity.ContextRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bound, present := tenancy.FromContext(ctx)
	if !present || principal == nil || principal.UserID == "" || bound.String() != principal.TenantID || record.TenantID != principal.TenantID || record.ContextID == "" {
		return entity.ErrScopeMismatch
	}
	for _, permission := range []string{permAIQuery, permFlowRead, "entities.read", "events.read"} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
			return err
		}
	}
	return ctx.Err()
}
