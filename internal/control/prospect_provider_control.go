// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	prospectProviderAccessAudit  = "lifecycle.prospect_provider_access"
	prospectProviderRequestAudit = "lifecycle.prospect_provider_requested"
)

type prospectProviderAccessInput struct {
	EngagementRevision int64 `json:"engagement_revision"`
	AccessRevision     int64 `json:"access_revision"`
	Allowed            *bool `json:"allowed"`
}

type prospectProviderRequest struct {
	tenant  string
	request reporting.ProspectProviderRequest
}

type prospectProviderQueue struct{ server *Server }

// ProspectProviderQueue attaches only through the existing provider build
// seam. Its worker can assess existing due terms using current tenant owner
// authorization. It has no collection, download or lifecycle decision method.
func (s *Server) ProspectProviderQueue() reporting.ProspectProviderQueue {
	if s == nil || s.pool == nil || s.fairnessGate == nil {
		return nil
	}
	if s.prospectProviderRequests == nil {
		s.prospectProviderRequests = make(chan prospectProviderRequest, 32)
	}
	return prospectProviderQueue{server: s}
}

func (s *Server) handleProspectProviderAccess(w http.ResponseWriter, r *http.Request) error {
	if s.prospectProviderRequests == nil {
		return apierror.NotFound("prospect operation unavailable")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.UserID == "" {
		return apierror.Forbidden("a current named account is required")
	}
	var result store.ProspectProviderAccess
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = (store.ProspectEngagements{}).ProviderAccess(ctx, sc, actor.UserID)
		return err
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) handleSetProspectProviderAccess(w http.ResponseWriter, r *http.Request) error {
	if s.prospectProviderRequests == nil {
		return apierror.NotFound("prospect operation unavailable")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.UserID == "" || actor.ViaBearerToken {
		return apierror.Forbidden("provider report access requires an interactive owner")
	}
	var input prospectProviderAccessInput
	if err := decodeJSONLimit(r, 1024, &input); err != nil {
		return err
	}
	if input.EngagementRevision < 1 || input.AccessRevision < 0 || input.Allowed == nil {
		return apierror.Validation("select both current revisions and explicitly grant or withdraw provider access")
	}
	var result store.ProspectProviderAccess
	err := s.withProspectAuthority(r, false, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = (store.ProspectEngagements{}).SetProviderAccess(ctx, sc, actor.UserID, input.EngagementRevision, input.AccessRevision, *input.Allowed)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, prospectProviderAccessAudit, sc.Tenant.String(), map[string]any{
			"engagement_revision": result.EngagementRevision, "provider_access_revision": result.Revision, "allowed": result.Allowed,
		})
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (q prospectProviderQueue) Status(ctx context.Context, tenant string) (reporting.ProspectProviderStatus, error) {
	var result reporting.ProspectProviderStatus
	s := q.server
	ctx, err := s.scopeProspectProvider(ctx, tenant)
	if err != nil {
		return result, err
	}
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, _, err = s.prospectProviderStatusInScope(ctx, sc)
		return err
	})
	return result, err
}

func (q prospectProviderQueue) RequestAssessment(ctx context.Context, tenant, operator string, request reporting.ProspectProviderRequest) (reporting.ProspectProviderStatus, error) {
	var result reporting.ProspectProviderStatus
	if !reportRequirementUUID(request.ID) || request.EngagementRevision < 1 || request.AccessRevision < 1 || operator == "" {
		return result, apierror.Validation("an exact provider request and operator are required")
	}
	s := q.server
	ctx, err := s.scopeProspectProvider(ctx, tenant)
	if err != nil {
		return result, err
	}
	var queued bool
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		var storedRequest string
		var err error
		result, storedRequest, err = s.prospectProviderStatusInScope(ctx, sc)
		if err != nil {
			return err
		}
		if result.EngagementRevision != request.EngagementRevision || result.AccessRevision != request.AccessRevision {
			return apierror.NotFound("prospect operation unavailable")
		}
		if storedRequest == request.ID {
			var ownedReceipt bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events
			  WHERE tenant_id=$1 AND action=$2 AND target=$3 AND data->>'operator'=$4
			    AND data->>'engagement_revision'=$5::bigint::text
			    AND data->>'provider_access_revision'=$6::bigint::text)`,
				tenant, prospectProviderRequestAudit, request.ID, operator, request.EngagementRevision, request.AccessRevision).Scan(&ownedReceipt); err != nil {
				return err
			}
			if !ownedReceipt {
				return apierror.NotFound("prospect operation unavailable")
			}
			result.RequestID = storedRequest
			return nil
		}
		queued, err = (store.ProspectEngagements{}).QueueProviderAssessment(ctx, sc, request.ID, request.EngagementRevision, request.AccessRevision)
		if err != nil || !queued {
			return err
		}
		result.Pending = true
		result.RequestID = request.ID
		return audit.TenantRecord(ctx, sc, "provider-report-trigger", prospectProviderRequestAudit, request.ID, map[string]any{
			"operator": operator, "engagement_revision": request.EngagementRevision, "provider_access_revision": request.AccessRevision,
		})
	})
	if err == nil && queued {
		// The scoped request is durable. A full channel only delays it to the
		// ordinary supervisor pass. The request never starts an extra worker.
		select {
		case s.prospectProviderRequests <- prospectProviderRequest{tenant: tenant, request: request}:
		default:
		}
	}
	return result, err
}

func (s *Server) scopeProspectProvider(ctx context.Context, tenant string) (context.Context, error) {
	if !reportRequirementUUID(tenant) {
		return nil, apierror.Validation("a canonical tenant is required")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != tenant {
		return nil, entity.ErrScopeMismatch
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	if err := s.currentReportTenant(ctx, tenant); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (s *Server) prospectProviderStatusInScope(ctx context.Context, sc tenancy.Scope) (reporting.ProspectProviderStatus, string, error) {
	var result reporting.ProspectProviderStatus
	status, owner, err := (store.ProspectEngagements{}).ProviderStatus(ctx, sc)
	if err != nil {
		return result, "", err
	}
	authority, err := readCurrentUserAuthorityScope(ctx, sc, owner)
	if err != nil {
		return result, "", err
	}
	ctx, actor, err := authority.backgroundContext(ctx, []string{"metrics.read"})
	if err != nil {
		return result, "", err
	}
	if err := s.authorize(ctx, actor, "metrics.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}); err != nil {
		return result, "", err
	}
	return reporting.ProspectProviderStatus{
		TenantID: sc.Tenant.String(), Phase: status.Phase, EndsAt: status.EndsAt, Pending: status.Pending,
		EngagementRevision: status.Revision, AccessRevision: status.AccessRevision,
	}, status.RequestID, nil
}
