// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/remediation"
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
	var in struct {
		Fingerprint string `json:"review_fingerprint"`
		Note        string `json:"note"`
	}
	if err := decodeJSONLimit(r, 4096, &in); err != nil {
		return err
	}
	result, err := service.ApproveFlowSpec(ctx, actor.TenantID, "user:"+actor.Email, r.PathValue("id"),
		in.Fingerprint, in.Note, s.pathAlertRequestCredential(r, actor))
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
