// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
)

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
	var input alert.DependencyPolicyInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	out, err := s.setAlertDependencyPolicy(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"), input)
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
