package control

import (
	_ "embed"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"net/http"
)

// openapiJSON is the OpenAPI 3.1 description of the control-plane API. Resource
// endpoints (under /v1) are added by their sprints (S9+); operational endpoints
// are documented here. Keeping it in lockstep with the handlers upholds the
// "no undocumented routes" rule (CLAUDE.md §6, §8).
//
//go:embed openapi.json
var openapiJSON []byte

// handleOpenAPI serves the embedded OpenAPI document.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) error {
	// SEC-008: the full API surface map is gated behind auth outside dev mode.
	if s.cfg.AuthMode != "dev" && s.resolvePrincipal(r) == nil {
		return apierror.Unauthorized("authentication required for the OpenAPI document")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(openapiJSON)
	return nil
}
