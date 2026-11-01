// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleListEntityContexts(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return apierror.BadRequest("invalid entity context page limit")
		}
	}
	page, err := store.NewEntityRegistry(s.pool).ListEntityContexts(
		tenancy.WithTenant(r.Context(), tenancy.ID(tid)), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		return entityAPIError(err)
	}
	principal := auth.PrincipalFrom(r.Context())
	for _, item := range page.Items {
		resource := entityContextResource(item)
		if err := s.authorize(r.Context(), principal, ai.PermEntitiesRead,
			auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

// handleListEntities walks only one explicit routing context. A page never
// becomes a cross-VRF inventory when the caller omits context_id.
func (s *Server) handleListEntities(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return apierror.BadRequest("invalid entity page limit")
		}
	}
	scope := entity.Scope{TenantID: tid, ContextID: r.URL.Query().Get("context_id")}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tid))
	page, err := store.NewEntityRegistry(s.pool).ListEntities(ctx, scope,
		r.URL.Query().Get("cursor"), limit)
	if err != nil {
		return entityAPIError(err)
	}
	resource, err := s.entityResource(ctx, page.Scope)
	if err != nil {
		return err
	}
	if err := s.authorize(r.Context(), auth.PrincipalFrom(r.Context()),
		ai.PermEntitiesRead, auth.RBACGlobal, resource); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

// handleGetEntity returns a canonical, tenant/context-owned record. An SNMP
// interface has a generic ifIndex label; its observed ifName/ifDescr are only
// on the source-permission-gated evidence page.
func (s *Server) handleGetEntity(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	scope := entity.Scope{TenantID: tid, ContextID: r.URL.Query().Get("context_id")}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tid))
	record, err := store.NewEntityRegistry(s.pool).GetEntity(ctx, scope, r.PathValue("id"))
	if err != nil {
		return entityAPIError(err)
	}
	resource, err := s.entityResource(ctx, record.Scope)
	if err != nil {
		return err
	}
	if err := s.authorize(r.Context(), auth.PrincipalFrom(r.Context()),
		ai.PermEntitiesRead, auth.RBACGlobal, resource); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, record)
	return nil
}

func entityDetailRequest(s *Server, r *http.Request) (entity.Scope, int, error) {
	tid, err := s.principalTenant(r)
	if err != nil {
		return entity.Scope{}, 0, err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return entity.Scope{}, 0, apierror.BadRequest("invalid entity detail page limit")
		}
	}
	return entity.Scope{TenantID: tid, ContextID: r.URL.Query().Get("context_id")}, limit, nil
}

func (s *Server) handleListEntityEvidence(w http.ResponseWriter, r *http.Request) error {
	scope, limit, err := entityDetailRequest(s, r)
	if err != nil {
		return err
	}
	page, err := store.NewEntityRegistry(s.pool).ListEntityEvidence(
		tenancy.WithTenant(r.Context(), tenancy.ID(scope.TenantID)), scope,
		r.PathValue("id"), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		return entityAPIError(err)
	}
	principal := auth.PrincipalFrom(r.Context())
	resource, err := s.entityResource(tenancy.WithTenant(r.Context(), tenancy.ID(scope.TenantID)), page.Scope)
	if err != nil {
		return err
	}
	if err := s.authorize(r.Context(), principal, ai.PermEntitiesRead,
		auth.RBACGlobal, resource); err != nil {
		return err
	}
	for _, item := range page.Items {
		permission := entitySourcePermission(item.SourceKey.Kind)
		if permission == "" {
			return apierror.Forbidden("entity evidence source is not authorized")
		}
		if err := s.authorize(r.Context(), principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
		if item.SupportEvidenceID != "" {
			if err := s.authorize(r.Context(), principal,
				entitySourcePermission(entity.DeviceTarget), auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) handleListEntityLinks(w http.ResponseWriter, r *http.Request) error {
	scope, limit, err := entityDetailRequest(s, r)
	if err != nil {
		return err
	}
	page, err := store.NewEntityRegistry(s.pool).ListEntityLinks(
		tenancy.WithTenant(r.Context(), tenancy.ID(scope.TenantID)), scope,
		r.PathValue("id"), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		return entityAPIError(err)
	}
	principal := auth.PrincipalFrom(r.Context())
	resource, err := s.entityResource(tenancy.WithTenant(r.Context(), tenancy.ID(scope.TenantID)), page.Scope)
	if err != nil {
		return err
	}
	if err := s.authorize(r.Context(), principal, ai.PermEntitiesRead,
		auth.RBACGlobal, resource); err != nil {
		return err
	}
	for _, item := range page.Items {
		permission := entitySourcePermission(item.SourceKind)
		if permission == "" {
			return apierror.Forbidden("entity link source is not authorized")
		}
		if err := s.authorize(r.Context(), principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

// handleResolveEntity exposes one unambiguous candidate or an honest conflict.
// Every returned source-specific permission is checked before any provenance
// leaves the handler. A truncated conflict advertises more candidates.
func (s *Server) handleResolveEntity(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	scope := entity.Scope{TenantID: tid, ContextID: r.URL.Query().Get("context_id")}
	alias := entity.AliasKey{
		Kind:  entity.AliasKind(r.URL.Query().Get("kind")),
		Value: r.URL.Query().Get("value"),
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tid))
	result, err := store.NewEntityRegistry(s.pool).ResolveAlias(ctx, scope, alias)
	if err != nil {
		return entityAPIError(err)
	}
	resource, err := s.entityResource(ctx, result.Scope)
	if err != nil {
		return err
	}
	if err := s.authorizeEntityResolution(r.Context(), auth.PrincipalFrom(r.Context()),
		result, resource); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

var entityEvidenceSourceKinds = []entity.SourceKind{
	entity.DeviceTarget, entity.FlowExporter, entity.PathAgent,
	entity.BMPPeer, entity.AgentSite,
}

func entityScopeResource(scope entity.Scope) map[string]string {
	return map[string]string{
		auth.ResourceTenantKey: scope.TenantID,
		"context_id":           scope.ContextID,
	}
}

func entityContextResource(record entity.ContextRecord) map[string]string {
	resource := entityScopeResource(entity.Scope{TenantID: record.TenantID, ContextID: record.ContextID})
	resource["site_id"], resource["vrf_id"] = record.SiteID, record.VRFID
	resource["site_label"], resource["vrf_label"] = record.SiteLabel, record.VRFLabel
	return resource
}

func (s *Server) entityResource(ctx context.Context, scope entity.Scope) (map[string]string, error) {
	record, err := store.NewEntityRegistry(s.pool).GetEntityContext(ctx, scope)
	if err != nil {
		return nil, entityAPIError(err)
	}
	return entityContextResource(record), nil
}

// A bounded conflict returns three representatives and a more_candidates
// marker. When the fourth distinct entity exists, its source plane is not
// exposed in the bounded result. Require all possible source permissions in
// that case so an unreturned candidate cannot silently affect an answer for
// a source-limited principal.
func (s *Server) authorizeEntityResolution(ctx context.Context, principal *auth.Principal,
	result entity.Resolution, resource map[string]string) error {
	if err := s.authorize(ctx, principal, ai.PermEntitiesRead,
		auth.RBACGlobal, resource); err != nil {
		return err
	}
	for _, candidate := range result.Candidates {
		permission := entitySourcePermission(candidate.SourceKey.Kind)
		if permission == "" {
			return apierror.Forbidden("entity evidence source is not authorized")
		}
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
		if candidate.SupportEvidenceID != "" {
			if err := s.authorize(ctx, principal,
				entitySourcePermission(entity.DeviceTarget), auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
	}
	if result.MoreCandidates {
		for _, kind := range entityEvidenceSourceKinds {
			if err := s.authorize(ctx, principal, entitySourcePermission(kind),
				auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
	}
	return nil
}

func entitySourcePermission(kind entity.SourceKind) string {
	switch kind {
	case entity.DeviceTarget:
		return ai.PermMetricsRead
	case entity.FlowExporter:
		return permFlowRead
	case entity.PathAgent:
		return permTestRead
	case entity.BMPPeer:
		return ai.PermEventsRead
	case entity.AgentSite:
		return permAgentRead
	default:
		return ""
	}
}

func entityAPIError(err error) error {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("entity not found in this routing context")
	case errors.Is(err, entity.ErrInvalidScope), errors.Is(err, entity.ErrInvalidAlias),
		errors.Is(err, entity.ErrInvalidClaim), errors.Is(err, entity.ErrInvalidPage):
		return apierror.BadRequest(err.Error())
	case errors.Is(err, entity.ErrScopeMismatch):
		return apierror.Forbidden("entity tenant scope mismatch")
	case errors.Is(err, store.ErrEntityRegistryUnavailable):
		return apierror.Unavailable("entity registry is not configured")
	default:
		return err
	}
}
