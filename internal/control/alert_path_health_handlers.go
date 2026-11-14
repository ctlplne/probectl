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
)

func (s *Server) pathAlertRequestCredential(request *http.Request, actor *auth.Principal) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := s.resolvePrincipal(request.Clone(ctx))
		if current == nil {
			return unauthenticated(request)
		}
		if actor == nil || !auth.SamePrincipalAuthority(actor, current) {
			return apierror.Forbidden("originating credential authority changed")
		}
		return nil
	}
}

func (s *Server) handleGetAlertPathHealthSource(w http.ResponseWriter, r *http.Request) error {
	if err := validateAlertTagRuleID(r.PathValue("id")); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	out, err := s.readAlertPathHealthSource(r.Context(), actor, r.PathValue("id"), s.pathAlertRequestCredential(r, actor), nil)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handlePutAlertPathHealthSource(w http.ResponseWriter, r *http.Request) error {
	if err := validateAlertTagRuleID(r.PathValue("id")); err != nil {
		return err
	}
	var input alert.PathHealthSourceInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	out, err := s.setAlertPathHealthSource(r.Context(), actor, r.PathValue("id"), input, s.pathAlertRequestCredential(r, actor), nil)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleDeleteAlertPathHealthSource(w http.ResponseWriter, r *http.Request) error {
	if err := validateAlertTagRuleID(r.PathValue("id")); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	out, err := s.clearAlertPathHealthSource(r.Context(), actor, r.PathValue("id"), s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
