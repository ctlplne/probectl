// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type complianceFlowSourceSnapshot struct {
	sources       []store.IncidentImpactSource
	owners        []store.CapturedFlowOwner
	sourceDigest  string
	captureDigest string
}

func (s *Server) loadComplianceFlowSourceSnapshot(ctx context.Context, actor *auth.Principal, members []store.IncidentImpactEntity, reads []flowstore.RoutingCaptureRead, budget flowstore.ExplorerBudget) (complianceFlowSourceSnapshot, error) {
	var result complianceFlowSourceSnapshot
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return result, err
	}
	if s.pool == nil || budget.Validate() != nil {
		return result, apierror.Unavailable("compliance flow source storage or admission is unavailable")
	}
	if err := s.currentReportTenant(ctx, actor.TenantID); err != nil {
		return result, err
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = s.complianceFlowSourcesInScope(ctx, sc, actor, members, reads, budget)
		return err
	})
	if err != nil {
		return complianceFlowSourceSnapshot{}, err
	}
	return result, nil
}

func (s *Server) complianceFlowSourcesInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, members []store.IncidentImpactEntity, reads []flowstore.RoutingCaptureRead, budget flowstore.ExplorerBudget) (complianceFlowSourceSnapshot, error) {
	var result complianceFlowSourceSnapshot
	if actor == nil || actor.TenantID != sc.Tenant.String() || len(members) == 0 {
		return result, entity.ErrScopeMismatch
	}
	ctx, authorize, err := s.complianceFlowAuthorizer(ctx, sc, actor)
	if err != nil {
		return result, err
	}
	limit := budget.MemoryBytes / 4
	sources, err := store.CurrentFlowSourcesInScope(ctx, sc, members, entity.InterfaceRolePolicyBudget{MemoryBytes: limit, WorkUnits: limit}, authorize)
	if err != nil {
		return result, err
	}
	sourceDigest, err := hashFlowRoleInputs(ctx, nil, sources, limit)
	if err != nil {
		return result, err
	}
	result.sources, result.sourceDigest = sources, hex.EncodeToString(sourceDigest)
	if len(reads) == 0 {
		return result, nil
	}
	return loadComplianceFlowCaptureOwners(ctx, sc, result, reads, budget, authorize)
}

func (s *Server) authorizeComplianceFlow(ctx context.Context, actor *auth.Principal, resource map[string]string) error {
	for _, permission := range []string{permAuditRead, permFlowRead, "entities.read"} {
		if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func loadComplianceFlowCaptureOwners(ctx context.Context, sc tenancy.Scope, snapshot complianceFlowSourceSnapshot, reads []flowstore.RoutingCaptureRead, budget flowstore.ExplorerBudget,
	authorize func(context.Context, entity.ContextRecord, store.IncidentImpactEntity) error) (complianceFlowSourceSnapshot, error) {
	limit := budget.MemoryBytes / 2
	owners, err := (store.CapturedFlowOwners{}).ReadInScope(ctx, sc, reads, store.BGPRoutingBudget{MemoryBytes: limit, WorkUnits: limit, StateBytes: limit},
		selectedFlowOwnerAuthorization(snapshot.sources, authorize))
	if err != nil {
		return complianceFlowSourceSnapshot{}, err
	}
	digest, err := hashFlowRoleInputs(ctx, nil, owners, budget.MemoryBytes/4)
	if err != nil {
		return complianceFlowSourceSnapshot{}, err
	}
	snapshot.owners, snapshot.captureDigest = owners, hex.EncodeToString(digest)
	return snapshot, nil
}

func (s *Server) complianceFlowAuthorizer(ctx context.Context, sc tenancy.Scope, actor *auth.Principal) (context.Context, func(context.Context, entity.ContextRecord, store.IncidentImpactEntity) error, error) {
	if actor == nil || actor.TenantID != sc.Tenant.String() || actor.UserID == "" {
		return nil, nil, entity.ErrScopeMismatch
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return nil, nil, err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorizeComplianceFlow(ctx, principal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
		return nil, nil, err
	}
	authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity) error {
		if record.TenantID != principal.TenantID || record.ContextID != member.ContextID {
			return entity.ErrScopeMismatch
		}
		resource := entityContextResource(record)
		resource["entity_id"] = member.EntityID
		return s.authorizeComplianceFlow(ctx, principal, resource)
	}

	return ctx, authorize, nil
}

func (s *Server) authorizeDashboardComplianceDefinition(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, definition dashboardDefinition) error {
	if definition.ComplianceControl == "" {
		if definition.ComplianceFlow != nil {
			return apierror.Forbidden("compliance flow evidence scope is unavailable")
		}
		return nil
	}
	if definition.ComplianceControl == compliance.CMMCAuditControl {
		return s.authorizeComplianceControlScope(ctx, sc, actor, definition.ComplianceControl)
	}
	if definition.ComplianceFlow == nil {
		return apierror.Forbidden("compliance flow evidence scope is unavailable")
	}
	return s.authorizeDashboardFlowPoints(ctx, sc, actor, definition)
}

func (s *Server) authorizeDashboardFlowPoints(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, definition dashboardDefinition) error {
	members, err := complianceFlowMembers(definition.ComplianceFlow.Sources)
	if err != nil {
		return err
	}
	ctx, authorize, err := s.complianceFlowAuthorizer(ctx, sc, actor)
	if err != nil {
		return entityAPIError(err)
	}
	registry := store.NewEntityRegistry(nil)
	for _, member := range members {
		record, err := registry.GetEntityContextInScope(ctx, sc, member.ContextID)
		if err != nil {
			return entityAPIError(err)
		}
		if err := authorize(ctx, record, member); err != nil {
			return entityAPIError(err)
		}
		point, err := registry.GetEntityInScope(ctx, sc, entity.Scope{TenantID: record.TenantID, ContextID: record.ContextID}, member.EntityID)
		if err != nil {
			return entityAPIError(err)
		}
		if point.Kind != entity.Device && point.Kind != entity.Interface {
			return apierror.Validation("each compliance flow source must be a canonical device or interface")
		}
	}
	return ctx.Err()
}

func (s *Server) authorizeSavedComplianceFlowDefinition(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, raw json.RawMessage) error {
	var stored struct {
		Control string                              `json:"compliance_control"`
		Flow    *reporting.ComplianceFlowDefinition `json:"compliance_flow"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return apierror.Internal("stored dashboard compliance definition is invalid").Wrap(err)
	}
	if stored.Flow == nil {
		kind := compliance.ControlEvidenceSection(stored.Control)
		if kind == compliance.SectionSegmentation || kind == compliance.SectionNetworkMonitoring {
			return apierror.Forbidden("compliance flow evidence scope is unavailable")
		}
		return nil
	}
	return s.authorizeDashboardComplianceDefinition(ctx, sc, actor, dashboardDefinition{ComplianceControl: stored.Control, ComplianceFlow: stored.Flow})
}
