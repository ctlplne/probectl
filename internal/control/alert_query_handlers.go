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

func (s *Server) handleGetAlertQuerySource(w http.ResponseWriter, r *http.Request) error {
	if err := validateAlertTagRuleID(r.PathValue("id")); err != nil {
		return err
	}
	out, err := s.readAlertQuerySource(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handlePutAlertQuerySource(w http.ResponseWriter, r *http.Request) error {
	if err := validateAlertTagRuleID(r.PathValue("id")); err != nil {
		return err
	}
	var input alert.QuerySourceInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	out, err := s.setAlertQuerySource(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"), input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleDeleteAlertQuerySource(w http.ResponseWriter, r *http.Request) error {
	if err := validateAlertTagRuleID(r.PathValue("id")); err != nil {
		return err
	}
	out, err := s.clearAlertQuerySource(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
