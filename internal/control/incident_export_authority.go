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
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// A request-start principal cannot authorize signed bytes after a slow model,
// source read, signature or audit. Resolve the originating bearer/session again
// and load current policy and incident retention through tenant-scoped storage.
func (s *Server) revalidateIncidentExport(r *http.Request, original *incident.Incident) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || original == nil || original.TenantID != actor.TenantID || s.pool == nil {
		return apierror.Unauthorized("current incident export authority is required")
	}
	current := actor
	// The existing compiled-in local evaluation mode has no stored credential.
	// Release binaries cannot enter it; authenticated deployments always refresh
	// the actual bearer/session and fail closed on lookup failure or withdrawal.
	development := s.cfg.AuthMode == "dev" && DevModeAvailable()
	if !development {
		current = s.resolvePrincipal(r)
		if current == nil {
			return unauthenticated(r)
		}
		if !auth.SamePrincipalAuthority(actor, current) {
			return apierror.Forbidden("incident export credential authority changed")
		}
	}
	if s.requireMFA && !current.MFASatisfied {
		return apierror.Forbidden("multi-factor authentication required")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(r.Context(), current.TenantID)
	if err != nil {
		return err
	}
	if status != "active" {
		return apierror.Forbidden("incident export tenant is inactive")
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(current.TenantID))
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		principal := current
		if !development {
			authority, err := readCurrentUserAuthorityScope(ctx, sc, current.UserID)
			if err != nil {
				return err
			}
			ctx, principal, err = authority.requestContext(ctx, current)
			if err != nil {
				return err
			}
		}
		resource := map[string]string{auth.ResourceTenantKey: current.TenantID, "incident_id": original.ID}
		for _, permission := range []string{permIncidentRead, permAIQuery} {
			if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
		// The exact incident must still exist after encoding. A late erase must
		// never publish the retained pre-erasure body under an otherwise valid key.
		_, err := (store.Incidents{}).Get(ctx, sc, original.ID)
		return err
	})
}
