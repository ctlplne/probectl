// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (s *Server) handleCapacityAgreementBill(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreementMode(r, false)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	var input flow.CapacityBillRequest
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	result, err := s.checkCapacityAgreementBill(op, r.PathValue("id"), input)
	if err != nil {
		return capacityBillAPIError(err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return apierror.Unavailable("complete measured billing output is unavailable")
	}
	if int64(len(body)) >= op.budget.ResponseBytes || int64(len(body)) >= op.budget.MemoryBytes/16 {
		return apierror.TooLarge("complete measured billing output exceeds resource admission")
	}
	// Refresh the exact bearer/session, rather than treating the preflight
	// principal or the last current-user role read as a credential grant.
	current := s.resolvePrincipal(op.request)
	if current == nil {
		return unauthenticated(op.request)
	}
	if !auth.SamePrincipalAuthority(op.actor, current) {
		return apierror.Forbidden("credential authority changed; run a fresh bill check")
	}
	if !result.SourceValidUntil.After(time.Now().UTC()) {
		return apierror.Unavailable("counter source authority expired; run a fresh bill check")
	}
	if err := op.request.Context().Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
	return nil
}

func capacityBillAPIError(err error) error {
	if domain, ok := apierror.As(err); ok {
		return domain
	}
	if errors.Is(err, flowstore.ErrCounterHistoryBudget) || errors.Is(err, store.ErrCounterCaptureBudget) || errors.Is(err, store.ErrTagSnapshotBudget) {
		return apierror.TooLarge("complete measured billing exceeds resource admission")
	}
	if errors.Is(err, flow.ErrCapacityAgreementInvalid) || errors.Is(err, flow.ErrCapacityAgreementNotFound) || errors.Is(err, flow.ErrCapacityAgreementBudget) {
		return capacityAgreementAPIError(err)
	}
	return apierror.Unavailable("complete current counter evidence is unavailable for measured billing")
}
