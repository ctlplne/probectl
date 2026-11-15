// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

type reportOriginatingCredentialKey struct{}

// A renderer/source scan may outlive a bearer or session. Fresh user grants
// alone cannot prove that credential remains valid. Native handlers carry the
// transport's exact-credential guard; public HTTP resolves the original request.
func (s *Server) revalidateReportCredential(r *http.Request) error {
	if err := r.Context().Err(); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return unauthenticated(r)
	}
	if s.requireMFA && !actor.MFASatisfied {
		return apierror.Forbidden("multi-factor authentication required")
	}
	if guard, ok := r.Context().Value(reportOriginatingCredentialKey{}).(func(context.Context) error); ok {
		if guard == nil {
			return apierror.Forbidden("report originating credential is unavailable")
		}
		if err := guard(r.Context()); err != nil {
			return apierror.Forbidden("report originating credential changed").Wrap(err)
		}
		return r.Context().Err()
	}
	if s.cfg != nil && s.cfg.AuthMode == "dev" && DevModeAvailable() {
		return nil
	}
	current := s.resolvePrincipal(r)
	if current == nil {
		return unauthenticated(r)
	}
	if !auth.SamePrincipalAuthority(actor, current) {
		return apierror.Forbidden("report credential authority changed; retry with current credentials")
	}
	if s.requireMFA && !current.MFASatisfied {
		return apierror.Forbidden("multi-factor authentication required")
	}
	return r.Context().Err()
}
