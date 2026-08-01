// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
