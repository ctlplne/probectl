// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (s *Server) beginIncidentVerdictQuery(ctx context.Context, actor *auth.Principal) (func(), error) {
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeIncidentVerdict(ctx, actor, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
		return nil, err
	}
	if s.fairnessGate == nil {
		return nil, apierror.Unavailable("incident verdict admission is unavailable")
	}
	return s.fairnessGate.BeginQuery(ctx, actor.TenantID)
}

func (s *Server) queryIncidentVerdict(ctx context.Context, actor *auth.Principal, id string, input incident.VerdictInput) (incident.FaultVerdict, error) {
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return incident.FaultVerdict{}, apierror.Unavailable("incident verdict admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	result, err := s.computeIncidentVerdict(ctx, actor, id, input.From, input.To, budget.MemoryBytes/5*4)
	if err != nil {
		return incident.FaultVerdict{}, flowRoutingQueryError(err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return incident.FaultVerdict{}, err
	}
	if int64(len(body)) > budget.ResponseBytes {
		return incident.FaultVerdict{}, flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	return result, ctx.Err()
}

func (s *Server) handleIncidentVerdict(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" {
		return apierror.Unauthorized("tenant identity required")
	}
	var input incident.VerdictInput
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &input); err != nil {
		return err
	}
	release, err := s.beginIncidentVerdictQuery(r.Context(), actor)
	if err != nil {
		if errors.Is(err, fairness.ErrQueryConcurrency) || errors.Is(err, fairness.ErrQueryBudget) {
			w.Header().Set("Retry-After", "1")
			return apierror.RateLimited("tenant incident verdict allowance exceeded; retry shortly")
		}
		return err
	}
	defer release()
	result, err := s.queryIncidentVerdict(r.Context(), actor, r.PathValue("id"), input)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
	return nil
}
