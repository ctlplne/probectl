//go:build devauth

// Dev auth (RED-001/SEC-001): the trusted-header, all-permissions principal
// for LOCAL EVALUATION ONLY. This file is the entire dev-auth surface and it
// is compiled in only with -tags devauth — release binaries contain none of
// this logic and none of these literals (the no-devauth-in-release CI gate
// verifies symbol + string absence on the untagged binary).
//
// Even with the tag, main refuses AuthMode=dev unless
// PROBECTL_DEV_AUTH_ACK=i-understand is set AND the listener binds loopback.

package control

import (
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func init() { devModeHook = devAuthPrincipal }

// devAuthPrincipal synthesizes the all-permissions dev principal. The tenant
// comes from the X-Probectl-Tenant override (UUID-validated; a malformed
// value is rejected fail-closed with a 400, handled here) or the default
// tenant.
func devAuthPrincipal(s *Server, w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	tid := tenancy.DefaultTenantID
	if h := r.Header.Get("X-Probectl-Tenant"); h != "" {
		if !uuidRe.MatchString(h) {
			writeError(w, r, apierror.BadRequest("X-Probectl-Tenant must be a tenant UUID"))
			return nil, true
		}
		tid = tenancy.ID(h)
	}
	perms := make(map[string]bool, len(allPermissionKeys))
	for _, k := range allPermissionKeys {
		perms[k] = true
	}
	return &auth.Principal{TenantID: tid.String(), UserID: "dev", Email: "dev@probectl.local",
		DisplayName: "Dev", Permissions: perms, Attributes: map[string]string{"mfa": "true"}}, false
}
