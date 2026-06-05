package control

import (
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/branding"
)

// The white-label brand surface (S-T4). PUBLIC and pre-auth by design: the
// login screen must render the tenant's brand before any session exists, so
// the brand is resolved from the serving HOST (custom-domain mapping) — or
// the caller's session tenant when one is present. Unlicensed/community
// deployments answer the default probectl brand (a brand is not a secret;
// hidden-unlicensed here means "default", never an error or a 404).
//
// Mounted off /v1 (like /auth/*): it bypasses the session-RBAC chain.
func (s *Server) handleBranding(w http.ResponseWriter, r *http.Request) error {
	host := branding.NormalizeHost(r.Host)
	tenantID := ""
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		tenantID = p.TenantID // a signed-in caller gets ITS tenant's brand
	}
	b := branding.Resolve(r.Context(), host, tenantID)
	// Brand responses are host-keyed: never let a shared cache serve tenant
	// A's brand on tenant B's domain.
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Add("Vary", "Host")
	writeJSON(w, http.StatusOK, b)
	return nil
}
