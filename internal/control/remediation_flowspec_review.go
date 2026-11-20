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

func (s *Server) handleProposeFlowSpecReview(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.flowSpecReviewActor(r)
	if err != nil {
		return err
	}
	var in remediation.FlowSpecProposalInput
	if err := decodeJSONLimit(r, 4096, &in); err != nil {
		return err
	}
	result, err := service.ProposeFlowSpec(r.Context(), actor.TenantID, "user:"+actor.Email, in, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusCreated, result)
	return nil
}

func (s *Server) handleGetFlowSpecReview(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.flowSpecReviewActor(r)
	if err != nil {
		return err
	}
	result, err := service.GetFlowSpecReview(r.Context(), actor.TenantID, r.PathValue("id"), s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) handleQualifyFlowSpec(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.flowSpecReviewActor(r)
	if err != nil {
		return err
	}
	var input remediation.FlowSpecQualificationInput
	if err := decodeJSONLimit(r, 2048, &input); err != nil {
		return err
	}
	result, err := service.QualifyFlowSpec(r.Context(), actor.TenantID, r.PathValue("id"), input, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) handleApproveFlowSpecReview(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.flowSpecReviewActor(r)
	if err != nil {
		return err
	}
	if actor.ViaBearerToken {
		return apierror.Forbidden("routing review approval requires a current interactive session")
	}
	ctx, err := s.routingReviewApprovalContext(r)
	if err != nil {
		return err
	}
	var in remediation.FlowSpecApprovalInput
	if err := decodeJSONLimit(r, 4096, &in); err != nil {
		return err
	}
	result, err := service.ApproveFlowSpec(ctx, actor.TenantID, "user:"+actor.Email, r.PathValue("id"),
		in, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) handleGetFlowSpecHandoff(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.flowSpecReviewActor(r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if !reportRequirementUUID(id) {
		return apierror.Validation("select an approved routing proposal")
	}
	result, err := service.GetFlowSpecHandoff(r.Context(), actor.TenantID, id, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) handleWithdrawFlowSpecHandoff(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.flowSpecReviewActor(r)
	if err != nil {
		return err
	}
	if actor.ViaBearerToken {
		return apierror.Forbidden("routing withdrawal requires a current interactive session")
	}
	id := r.PathValue("id")
	if !reportRequirementUUID(id) {
		return apierror.Validation("select an approved routing proposal")
	}
	ctx, err := s.routingReviewApprovalContext(r)
	if err != nil {
		return err
	}
	publication := remediation.RTBHImpactPublication{
		Publish: func(ctx context.Context, sc tenancy.Scope, permission string, commit func(context.Context, tenancy.Scope) error) error {
			if sc.Tenant.String() != actor.TenantID || permission != permRemediationApprove || commit == nil {
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
	result, err := service.WithdrawFlowSpecHandoff(ctx, actor.TenantID, "user:"+actor.Email, id, publication)
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) flowSpecReviewActor(r *http.Request) (remediation.FlowSpecReviews, *auth.Principal, error) {
	service, err := s.remediationSvc()
	if err != nil {
		return nil, nil, err
	}
	reviews, ok := service.(remediation.FlowSpecReviews)
	if !ok {
		return nil, nil, apierror.NotFound("traffic review is unavailable")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, nil, apierror.Unauthorized("a current tenant account is required")
	}
	return reviews, actor, nil
}
