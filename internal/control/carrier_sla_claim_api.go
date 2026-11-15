// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

func (s *Server) handleCarrierSLAClaim(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreementMode(r, false)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	if deadline, ok := op.request.Context().Deadline(); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(15 * time.Second))
	}
	var input flow.CarrierSLAClaimRequest
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	result, publication, err := s.prepareCarrierSLAClaim(op, input)
	if err != nil {
		return carrierSLAAPIError(err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if int64(len(body)) >= op.budget.ResponseBytes || int64(len(body)) >= op.budget.MemoryBytes/16 {
		return apierror.TooLarge("complete grouped SLA draft exceeds resource admission")
	}
	if err := publication(op.request.Context()); err != nil {
		return carrierSLAAPIError(err)
	}
	current := s.resolvePrincipal(op.request)
	if current == nil {
		return unauthenticated(op.request)
	}
	if !auth.SamePrincipalAuthority(op.actor, current) {
		return apierror.Forbidden("credential authority changed; run a fresh claim draft")
	}
	if !result.SourceValidUntil.After(time.Now().UTC()) {
		return apierror.Unavailable("claim source validity elapsed; run a fresh draft")
	}
	if err := op.request.Context().Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
	return nil
}
