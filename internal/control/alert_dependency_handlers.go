// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type dependencyWriteLeaseKey struct{}

func (s *Server) handleGetAlertDependencyPolicy(w http.ResponseWriter, r *http.Request) error {
	out, err := s.readAlertDependencyPolicy(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handlePutAlertDependencyPolicy(w http.ResponseWriter, r *http.Request) error {
	if err := validateAlertTagRuleID(r.PathValue("id")); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || s.fairnessGate == nil {
		return apierror.Unavailable("dependency configuration admission is unavailable")
	}
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return err
	}
	ctx := context.WithValue(r.Context(), dependencyWriteLeaseKey{}, actor.TenantID)
	r = r.WithContext(ctx)
	var input alert.DependencyPolicyInput
	if err := decodeJSONLimit(r, budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	out, err := s.setAlertDependencyPolicy(r.Context(), actor, r.PathValue("id"), input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleDeleteAlertDependencyPolicy(w http.ResponseWriter, r *http.Request) error {
	out, err := s.clearAlertDependencyPolicy(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
