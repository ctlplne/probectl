package control

import (
	"net/http"
	"regexp"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// STUB AUTH (S9). The /v1 API has no real authentication yet — S18 adds SSO/SCIM
// and a per-tenant IdP and will resolve the tenant from the authenticated
// session. Until then this dev stub resolves the seeded default tenant, with an
// optional X-Netctl-Tenant override (a tenant UUID) for multi-tenant dev/testing.
//
// Crucially, every /v1 handler is ALREADY tenant-scoped via internal/tenancy +
// Postgres RLS, so replacing this resolver with real identity in S18 is an
// internal change — handlers do not move off the tenant boundary.
var uuidRe = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (s *Server) resolveTenant(r *http.Request) (tenancy.ID, error) {
	h := r.Header.Get("X-Netctl-Tenant")
	if h == "" {
		return tenancy.DefaultTenantID, nil
	}
	if !uuidRe.MatchString(h) {
		return "", apierror.BadRequest("X-Netctl-Tenant must be a tenant UUID")
	}
	return tenancy.ID(h), nil
}
