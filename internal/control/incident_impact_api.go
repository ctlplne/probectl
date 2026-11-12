// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
)

func (s *Server) beginIncidentImpactQuery(ctx context.Context, actor *auth.Principal) (func(), error) {
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeIncidentImpact(ctx, actor, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
		return nil, err
	}
	if s.fairnessGate == nil {
		return nil, apierror.Unavailable("incident impact query admission is unavailable")
	}
	return s.fairnessGate.BeginQuery(ctx, actor.TenantID)
}

func (s *Server) handleIncidentImpact(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" {
		return apierror.Unauthorized("tenant identity required")
	}
	var input incident.ImpactInput
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &input); err != nil {
		return err
	}
	release, err := s.beginIncidentImpactQuery(r.Context(), actor)
	if err != nil {
		if errors.Is(err, fairness.ErrQueryConcurrency) || errors.Is(err, fairness.ErrQueryBudget) {
			w.Header().Set("Retry-After", "1")
			return apierror.RateLimited("tenant incident impact allowance exceeded; retry shortly")
		}
		return err
	}
	defer release()
	result, err := s.incidentImpact(r.Context(), actor, r.PathValue("id"), input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}
