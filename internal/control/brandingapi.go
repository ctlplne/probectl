// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/branding"
)

// handleBranding serves the public, deployment-wide UI theme contract. Product
// identity is fixed to probectl; the response never varies by host, tenant, or
// session. It is mounted off /v1 because the login shell also consumes it.
func (s *Server) handleBranding(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, branding.Deployment(s.cfg.ThemeOverrides))
	return nil
}
