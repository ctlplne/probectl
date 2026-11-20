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
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handlePreviewDiversion(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.diversionReviewActor(r)
	if err != nil {
		return err
	}
	var input remediation.DiversionPreviewInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	preview, err := service.PreviewDiversion(r.Context(), actor.TenantID, input, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, preview)
	return nil
}

func (s *Server) handleProposeDiversion(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.diversionReviewActor(r)
	if err != nil {
		return err
	}
	ctx, err := s.routingReviewApprovalContext(r)
	if err != nil {
		return err
	}
	var input remediation.DiversionProposalInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	proposal, err := service.ProposeDiversion(ctx, actor.TenantID, "user:"+actor.Email, input,
		s.pathAlertRequestCredential(r, actor), s.routingReviewAuthorityPublication(actor, permRemediationPropose))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusCreated, proposal)
	return nil
}

func (s *Server) handleGetDiversionReview(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.diversionReviewActor(r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if !reportRequirementUUID(id) {
		return apierror.Validation("select a local diversion proposal")
	}
	review, err := service.GetDiversionReview(r.Context(), actor.TenantID, id, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, review)
	return nil
}

func (s *Server) handleApproveDiversion(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.diversionReviewActor(r)
	if err != nil {
		return err
	}
	ctx, err := s.routingReviewApprovalContext(r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if !reportRequirementUUID(id) {
		return apierror.Validation("select a local diversion proposal")
	}
	var input remediation.DiversionApprovalInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	receipt, err := service.ApproveDiversion(ctx, actor.TenantID, "user:"+actor.Email, id, input,
		s.pathAlertRequestCredential(r, actor), s.routingReviewAuthorityPublication(actor, permRemediationApprove))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, receipt)
	return nil
}

func (s *Server) diversionReviewActor(r *http.Request) (remediation.DiversionReviews, *auth.Principal, error) {
	service, err := s.remediationSvc()
	if err != nil {
		return nil, nil, err
	}
	reviews, ok := service.(remediation.DiversionReviews)
	if !ok {
		return nil, nil, apierror.NotFound("local diversion preview is unavailable")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, nil, apierror.Unauthorized("a current tenant account is required")
	}
	return reviews, actor, nil
}

func (s *Server) routingReviewAuthorityPublication(actor *auth.Principal, required string) remediation.RTBHImpactPublication {
	return remediation.RTBHImpactPublication{
		Publish: func(ctx context.Context, sc tenancy.Scope, permission string, commit func(context.Context, tenancy.Scope) error) error {
			if sc.Tenant.String() != actor.TenantID || permission != required || commit == nil {
				return tenancy.ErrNoTenant
			}
			if err := s.lockRoutingReviewApprovalSession(ctx, sc, actor); err != nil {
				return err
			}
			authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
			if err != nil {
				return err
			}
			ctx, current, err := authority.requestContext(ctx, actor)
			if err != nil {
				return err
			}
			if err := s.authorize(ctx, current, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}); err != nil {
				return err
			}
			return commit(ctx, sc)
		},
	}
}
