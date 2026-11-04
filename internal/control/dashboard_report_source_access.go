// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Revalidation is source IO outside a publication transaction. It grants no
// publication authority and does not reinterpret a frozen source definition.
func (s *Server) revalidateReportFlowCapture(ctx context.Context, actor *auth.Principal, capture *reportFlowCapture) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || capture == nil || actor.UserID == "" || actor.TenantID != capture.TenantID || bound.String() != capture.TenantID || len(capture.Inputs) == 0 {
		return apierror.Forbidden("report source reader scope is unavailable")
	}
	access, ok := s.flowQueryViews.(flow.QueryViewAccessStore)
	if !ok || s.pool == nil {
		return apierror.Unavailable("current report source access is unavailable")
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return apierror.Unavailable("current report source cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	for _, table := range capture.Tables {
		if table.TenantID != capture.TenantID {
			return apierror.Forbidden("report source record scope is unavailable")
		}
	}
	if !slices.Contains(capture.Permissions, permAIQuery) || !slices.Contains(capture.Permissions, permFlowRead) ||
		slices.Contains(capture.Permissions, permTagsRead) && !capture.ContextsCaptured || len(capture.Contexts) > 0 && (!capture.ContextsCaptured || !slices.Contains(capture.Permissions, permTagsRead)) {
		return apierror.Forbidden("report source requirements are incomplete")
	}
	current, err := loadCurrentUserAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	resource := map[string]string{auth.ResourceTenantKey: principal.TenantID}
	for _, permission := range capture.Permissions {
		if permission != permAIQuery && !reportFlowReadPermission(permission) {
			return apierror.Forbidden("report source requirements are invalid")
		}
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	seen := make(map[string]string)
	for _, input := range capture.Inputs {
		if input.ID == "" || input.Period != "current" && input.Period != "previous" || input.From.IsZero() || !input.From.Before(input.To) {
			return apierror.Forbidden("report source identity is unavailable")
		}
		if _, err := flow.QueryViewVersion(input.Version); err != nil {
			return apierror.Forbidden("report source version is unavailable")
		}
		if slices.Contains(capture.Permissions, permTagsRead) {
			if _, err := flow.QueryViewVersion(input.TagRevision); err != nil || input.TagAsOf.IsZero() {
				return apierror.Forbidden("report source metadata capture is unavailable")
			}
		}
		if version := seen[input.ID]; version != "" {
			if version != input.Version {
				return apierror.Forbidden("report source versions disagree")
			}
			continue
		}
		item, err := access.GetQueryViewAccess(ctx, principal.TenantID, principal.UserID, input.ID)
		if err != nil {
			return s.mapFlowViewStoreError(ctx, principal, err)
		}
		if item.ID != input.ID || item.TenantID != principal.TenantID || item.OwnerID == "" || item.OwnerID != principal.UserID && item.Visibility != "tenant" {
			return apierror.Forbidden("current report source visibility is unavailable")
		}
		if _, err := flow.QueryViewVersion(item.Version); err != nil || item.Visibility != "private" && item.Visibility != "tenant" {
			return apierror.Forbidden("current report source metadata is invalid")
		}
		seen[input.ID] = input.Version
	}
	for _, requirement := range capture.Contexts {
		if err := s.revalidateReportContext(ctx, principal, requirement); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func reportFlowReadPermission(permission string) bool {
	return slices.Contains([]string{permFlowRead, permTagsRead, "metrics.read", "agent.read", "entities.read"}, permission)
}

func (s *Server) revalidateReportContext(ctx context.Context, p *auth.Principal, requirement reportContextRequirement) error {
	if requirement.ContextID == "" || requirement.Resource[auth.ResourceTenantKey] != p.TenantID || requirement.Resource["context_id"] != requirement.ContextID ||
		!slices.Contains(requirement.Permissions, permFlowRead) || !slices.Contains(requirement.Permissions, permTagsRead) {
		return apierror.Forbidden("report context requirements are unavailable")
	}
	if len(requirement.Resource) != 6 || requirement.Resource["site_id"] == "" || requirement.Resource["vrf_id"] == "" {
		return apierror.Forbidden("report context attributes are incomplete")
	}
	for _, key := range []string{"site_label", "vrf_label"} {
		if _, present := requirement.Resource[key]; !present {
			return apierror.Forbidden("report context labels are incomplete")
		}
	}
	record, err := store.NewEntityRegistry(s.pool).GetEntityContext(ctx, entity.Scope{TenantID: p.TenantID, ContextID: requirement.ContextID})
	if err != nil {
		return entityAPIError(err)
	}
	if record.TenantID != p.TenantID || record.ContextID != requirement.ContextID {
		return apierror.Forbidden("current report context scope is unavailable")
	}
	for _, resource := range []map[string]string{requirement.Resource, entityContextResource(record)} {
		for _, permission := range requirement.Permissions {
			if !reportFlowReadPermission(permission) {
				return apierror.Forbidden("report context requirements are invalid")
			}
			if err := s.authorize(ctx, p, permission, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
