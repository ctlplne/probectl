// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
)

func (s *Server) handleCarrierSLA(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreementMode(r, false)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	if deadline, ok := op.request.Context().Deadline(); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(15 * time.Second))
	}
	var input flow.CarrierSLARequest
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	result, publication, err := s.calculateCarrierSLA(op, r.PathValue("id"), input)
	if err != nil {
		return carrierSLAAPIError(err)
	}
	body, err := marshalCarrierSLAStatement(result, op.budget.MemoryBytes, op.budget.ResponseBytes)
	if err != nil {
		return err
	}
	if err := publication(op.request.Context()); err != nil {
		return carrierSLAAPIError(err)
	}
	current := s.resolvePrincipal(op.request)
	if current == nil {
		return unauthenticated(op.request)
	}
	if !auth.SamePrincipalAuthority(op.actor, current) {
		return apierror.Forbidden("credential authority changed; run a fresh SLA calculation")
	}
	if !result.SourceValidUntil.After(time.Now().UTC()) {
		return apierror.Unavailable("SLA source validity elapsed; run a fresh calculation")
	}
	if err := op.request.Context().Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

func carrierSLAAPIError(err error) error {
	if domain, ok := apierror.As(err); ok {
		return domain
	}
	if errors.Is(err, flow.ErrCarrierSLAInput) {
		return apierror.Validation("complete recorded SLA terms and supported original measurement bases are required")
	}
	if errors.Is(err, store.ErrClientReportBudget) || errors.Is(err, store.ErrIncidentImpactBudget) {
		return apierror.TooLarge("complete carrier SLA population exceeds resource admission")
	}
	if errors.Is(err, flow.ErrCapacityAgreementNotFound) || errors.Is(err, flow.ErrCapacityAgreementInvalid) || errors.Is(err, flow.ErrCapacityAgreementBudget) {
		return capacityAgreementAPIError(err)
	}
	return apierror.Unavailable("complete current carrier SLA source evidence is unavailable")
}
