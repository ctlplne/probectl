// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"

	"github.com/ctlplne/probectl/internal/branding"
)

// handleBranding serves the public, deployment-wide UI theme contract. Product
// identity is fixed to probectl; the response never varies by host, tenant, or
// session. It is mounted off /v1 because the login shell also consumes it.
func (s *Server) handleBranding(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, branding.Deployment(s.cfg.ThemeOverrides))
	return nil
}
