// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// OutputBrand uses the existing tenant authority and never changes the tenant
// that owns the message or report. A failed read uses probectl presentation.
func (s *Server) OutputBrand(ctx context.Context, tenantID string) branding.Branding {
	if s.customerBranding == nil || tenantID == "" {
		return branding.Default()
	}
	if tenant, ok := tenancy.FromContext(ctx); ok && tenant.String() != tenantID {
		return branding.Default()
	}
	scoped := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	brand, err := s.customerBranding.ForTenant(scoped, tenantID)
	if err != nil {
		return branding.Default()
	}
	return brand
}

func (s *Server) WithCustomerBranding(resolver customerBrandResolver) *Server {
	s.customerBranding = resolver
	if s.dispatcher != nil {
		s.dispatcher.WithBranding(s.OutputBrand)
	}
	return s
}

// handleBranding returns public display fields. An authenticated identity
// takes precedence over the hostname. A hostname never changes its tenant.
func (s *Server) handleBranding(w http.ResponseWriter, r *http.Request) error {
	fallback := branding.Deployment(s.cfg.ThemeOverrides)
	if s.customerBranding == nil {
		w.Header().Set("Cache-Control", "public, max-age=60")
		writeJSON(w, http.StatusOK, fallback)
		return nil
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Host, Cookie, Authorization")
	tenant, hostBrand, err := s.customerBranding.ForHost(r.Context(), r.Host)
	if err == nil {
		out := hostBrand
		if token := auth.TokenFromRequest(r); token != "" && s.sessions != nil {
			session, sessionErr := s.sessions.Resolve(r.Context(), token)
			// An unresolved cookie supplies no tenant. The public presentation
			// is still safe to show on the exact registered sign-in host.
			if sessionErr == nil && session != nil {
				switch {
				case tenant != "" && session.TenantID != tenant:
					out = fallback
					out.CustomerDomain = true
				case tenant == "":
					ctx := tenancy.WithTenant(r.Context(), tenancy.ID(session.TenantID))
					out, err = s.customerBranding.ForTenant(ctx, session.TenantID)
				}
				if err == nil && out.Customer != nil {
					w.Header().Set("X-Probectl-Brand-Tenant", session.TenantID)
				}
			}
		}
		if err == nil {
			writeJSON(w, http.StatusOK, out)
			return nil
		}
	}
	writeJSON(w, http.StatusOK, fallback)
	return nil
}

// brandLoginTenant is a hint for initial IdP selection, never a session or
// principal. Read the actual request host rather than forwarded header input.
func (s *Server) brandLoginTenant(r *http.Request) (string, error) {
	if s.customerBranding == nil {
		return "", nil
	}
	tenant, err := s.customerBranding.TenantForHost(r.Context(), r.Host)
	if err != nil {
		return "", apierror.Unavailable("sign-in routing is temporarily unavailable")
	}
	return tenant, nil
}

// writeCustomerLoginRefusal keeps the public brand on the recovery page when
// the same customer still owns the verified host. Tenant storage may be held
// during quarantine, so use only the existing public presentation lookup.
func (s *Server) writeCustomerLoginRefusal(w http.ResponseWriter, r *http.Request, mapped string, refusal error) bool {
	if mapped == "" || s.customerBranding == nil {
		return false
	}
	domain, ok := quarantineAPIError(refusal)
	if !ok {
		domain, ok = apierror.As(refusal)
	}
	if !ok || domain.Code != string(apierror.CodeTenantQuarantined) {
		return false
	}
	owner, brand, err := s.customerBranding.ForHost(r.Context(), r.Host)
	if err != nil || owner != mapped || brand.Customer == nil {
		return false
	}
	writeError(w, r.WithContext(branding.WithOutput(r.Context(), brand)), refusal)
	return true
}

// requireCustomerHost narrows where a tenant principal can be used. The
// principal still supplies the tenant to RBAC and every storage operation.
func requireCustomerHost(next apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		tenant := customerHostTenant(r.Context())
		if principal := auth.PrincipalFrom(r.Context()); principal != nil && tenant != "" && tenant != principal.TenantID {
			return apierror.Unauthorized("credentials are unavailable on this host")
		}
		return next(w, r)
	}
}

type customerHostTenantKey struct{}

func customerHostTenant(ctx context.Context) string {
	tenant, _ := ctx.Value(customerHostTenantKey{}).(string)
	return tenant
}

// bindCustomerHost records a restriction on credentials presented to the
// console API. The restriction never supplies a storage tenant or a principal.
func (s *Server) bindCustomerHost(r *http.Request) (*http.Request, error) {
	if s.customerBranding == nil || !strings.HasPrefix(r.URL.Path, "/v1/") {
		return r, nil
	}
	if r.Header.Get("Authorization") == "" && auth.TokenFromRequest(r) == "" &&
		auth.PrincipalFrom(r.Context()) == nil && (s.cfg.AuthMode != "dev" || devModeHook == nil) {
		return r, nil
	}
	tenant, err := s.customerBranding.TenantForHost(r.Context(), r.Host)
	if err != nil {
		return nil, apierror.Unavailable("customer host routing is temporarily unavailable")
	}
	if tenant == "" {
		return r, nil
	}
	return r.WithContext(context.WithValue(r.Context(), customerHostTenantKey{}, tenant)), nil
}
