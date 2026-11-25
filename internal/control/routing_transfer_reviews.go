// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/remediation"
)

type routingTransferProposalRequest struct {
	Selection          routingTransferDryRunInput `json:"selection"`
	PreviewFingerprint string                     `json:"preview_fingerprint"`
	MaxMovedBPS        string                     `json:"max_moved_bps"`
}

type routingTransferApprovalRequest struct {
	Fingerprint string `json:"fingerprint"`
	Note        string `json:"note,omitempty"`
}

type routingTransferReviewOperation struct {
	capacityAgreementOperation
	service remediation.RoutingTransferReviewService
	prepare remediation.RoutingTransferReviewPrepare
}

func (s *Server) beginRoutingTransferReview(r *http.Request, permission string, mutation bool) (routingTransferReviewOperation, error) {
	none := routingTransferReviewOperation{}
	service, err := s.remediationSvc()
	if err != nil {
		return none, err
	}
	reviews, reviewsAvailable := service.(remediation.RoutingTransferReviewService)
	dryRun, dryRunAvailable := service.(remediation.RoutingTransferDryRunner)
	if !reviewsAvailable || !dryRunAvailable {
		return none, apierror.NotFound("routing transfer review is unavailable")
	}
	if mutation {
		ctx, err := s.routingReviewApprovalContext(r)
		if err != nil {
			return none, err
		}
		r = r.WithContext(ctx)
	}
	// The review reads financial terms and needs only the financial read grant.
	op, err := s.beginCapacityAgreementMode(r, false)
	if err != nil {
		return none, capacityAgreementAPIError(err)
	}
	prepare := func(ctx context.Context, selection json.RawMessage) (remediation.RoutingTransferDryRun, remediation.RTBHImpactPublication, error) {
		var input routingTransferDryRunInput
		if err := json.Unmarshal(selection, &input); err != nil {
			return remediation.RoutingTransferDryRun{}, remediation.RTBHImpactPublication{}, apierror.Conflict("stored routing transfer selection is unavailable")
		}
		bound, err := s.prepareRoutingTransferPreview(ctx, op, input, dryRun, permission)
		return bound.preview, bound.publication, err
	}
	return routingTransferReviewOperation{capacityAgreementOperation: op, service: reviews, prepare: prepare}, nil
}

func (s *Server) handleProposeRoutingTransfer(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginRoutingTransferReview(r, permRemediationPropose, true)
	if err != nil {
		return err
	}
	defer op.done()
	var input routingTransferProposalRequest
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	selection, err := json.Marshal(input.Selection)
	if err != nil {
		return apierror.Validation("a complete routing transfer selection is required")
	}
	proposal, err := op.service.ProposeRoutingTransfer(op.request.Context(), op.actor.TenantID, "user:"+op.actor.Email, selection,
		input.PreviewFingerprint, input.MaxMovedBPS, op.prepare)
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusCreated, proposal)
	return nil
}

func (s *Server) handleGetRoutingTransferReview(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginRoutingTransferReview(r, permRemediationPropose, false)
	if err != nil {
		return err
	}
	defer op.done()
	review, err := op.service.GetRoutingTransfer(op.request.Context(), op.actor.TenantID, r.PathValue("id"), op.prepare)
	if err != nil {
		return mapRemediationErr(err)
	}
	body, err := json.Marshal(review)
	if err != nil || int64(len(body)) >= op.budget.ResponseBytes {
		return apierror.Unavailable("complete routing review exceeds output admission")
	}
	return s.writeRoutingTransferReviewRead(w, op.capacityAgreementOperation, body, review.ValidUntil)
}

func (s *Server) handleApproveRoutingTransfer(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginRoutingTransferReview(r, permRemediationApprove, true)
	if err != nil {
		return err
	}
	defer op.done()
	var input routingTransferApprovalRequest
	if err := decodeJSONLimit(op.request, 4096, &input); err != nil {
		return err
	}
	proposal, err := op.service.ApproveRoutingTransfer(op.request.Context(), op.actor.TenantID, "user:"+op.actor.Email, r.PathValue("id"),
		input.Fingerprint, input.Note, op.prepare)
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, proposal)
	return nil
}
