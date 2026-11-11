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
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type capacityForecastOperation struct {
	request *http.Request
	actor   *auth.Principal
	budget  flowstore.ExplorerBudget
	done    func()
}

func (s *Server) beginCapacityForecast(r *http.Request) (capacityForecastOperation, error) {
	none := capacityForecastOperation{}
	actor := auth.PrincipalFrom(r.Context())
	ctx, err := bindFlowRoleContext(r.Context(), actor)
	if err != nil {
		return none, err
	}
	if actor.UserID == "" {
		return none, apierror.Forbidden("a current tenant user is required")
	}
	if s.pool == nil || s.fairnessGate == nil {
		return none, apierror.Unavailable("capacity storage or fairness admission is unavailable")
	}
	if s.requireMFA && !actor.MFASatisfied {
		return none, apierror.Forbidden("multi-factor authentication required")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if budget.Validate() != nil {
		return none, apierror.Unavailable("capacity operation admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		cancel()
		return none, tagQueryAdmissionError(err)
	}
	return capacityForecastOperation{request: r.WithContext(ctx), actor: actor, budget: budget, done: func() { release(); cancel() }}, nil
}

func (s *Server) handleCapacityForecast(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityForecast(r)
	if err != nil {
		return capacityBillAPIError(err)
	}
	defer op.done()
	var input flow.CapacityForecastRequest
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	result, err := s.measureCapacityForecast(op, input)
	if err != nil {
		return capacityBillAPIError(err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return apierror.Unavailable("complete capacity forecast output is unavailable")
	}
	if int64(len(body)) >= op.budget.ResponseBytes || int64(len(body)) >= op.budget.MemoryBytes/16 {
		return apierror.TooLarge("complete forecast output exceeds resource admission")
	}
	current := s.resolvePrincipal(op.request)
	if current == nil {
		return unauthenticated(op.request)
	}
	if !auth.SamePrincipalAuthority(op.actor, current) {
		return apierror.Forbidden("credential authority changed; run a fresh forecast")
	}
	if !result.SourceValidUntil.After(time.Now().UTC()) {
		return apierror.Unavailable("forecast source authority expired; retry")
	}
	if err := op.request.Context().Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
	return nil
}
