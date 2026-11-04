// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strconv"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func dashboardManifestSourceSlots(refs []reportFlowSourceRef) []dashboardManifestFlowSource {
	if len(refs) == 0 {
		return nil
	}
	slots := make([]dashboardManifestFlowSource, len(refs))
	for i := range refs {
		slots[i].Slot = "flow-" + strconv.Itoa(i+1)
	}
	return slots
}

func dashboardManifestSourceRefs(slots []dashboardManifestFlowSource, bindings map[string]reportFlowSourceRef) ([]reportFlowSourceRef, error) {
	if len(slots) != len(bindings) {
		return nil, apierror.Validation("native dashboard requires exactly one explicit destination binding for every source slot")
	}
	if len(slots) > maxDashboardManifestBytes/64 {
		return nil, apierror.Validation("native dashboard source slots exceed the document budget")
	}
	if len(slots) == 0 {
		return nil, nil
	}
	refs := make([]reportFlowSourceRef, len(slots))
	for i, slot := range slots {
		if slot.Slot != "flow-"+strconv.Itoa(i+1) {
			return nil, apierror.Validation("native source slots require canonical ordered flow-N names")
		}
		ref, ok := bindings[slot.Slot]
		if !ok {
			return nil, apierror.Validation("native source slot has no explicit destination binding")
		}
		refs[i] = ref
	}
	return refs, nil
}

// Configuration binds only current destination metadata, never telemetry or a
// durable source-read grant. Future generation and readers independently check
// current source execution/context authority. No nested pool call is permitted.
func (s *Server) validateDashboardFlowSourceRefs(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, refs []reportFlowSourceRef) error {
	if len(refs) == 0 {
		return nil
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || actor == nil || actor.TenantID != tenant.String() || actor.UserID == "" {
		return apierror.Forbidden("dashboard source binding scope is unavailable")
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return apierror.Unavailable("dashboard source binding cost policy is unavailable")
	}
	if s.fairnessGate == nil {
		return apierror.Unavailable("dashboard source binding admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return tagQueryAdmissionError(err)
	}
	defer release()
	access, ok := s.flowQueryViews.(reportScopedSourceAccess)
	if !ok {
		return apierror.Unavailable("dashboard source metadata is unavailable")
	}
	authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := authority.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	resource := map[string]string{auth.ResourceTenantKey: tenant.String()}
	for _, permission := range []string{permAIQuery, permFlowRead} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	for _, ref := range refs {
		current, err := access.GetQueryViewAccessInScope(ctx, sc, principal.UserID, ref.ID)
		if err != nil {
			return s.mapFlowViewStoreError(ctx, principal, err)
		}
		if current.Version != ref.Version {
			return apierror.Conflict("destination report source changed; select its current exact version")
		}
	}
	return ctx.Err()
}
