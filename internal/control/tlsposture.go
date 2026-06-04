package control

import (
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/threat"
)

// TLS/cert posture inventory API (S-FE2): the read side of S27. The inventory
// is the posture store the TLS consumer maintains from the result stream —
// the handler only serves the CALLER's tenant partition (tenant first, then
// the threat.read RBAC check on the route — CLAUDE.md §7 guardrails 1, 5).

// WithTLSPosture attaches the posture inventory backing GET /v1/tls/posture.
// nil is a no-op (the endpoint reports collector_running=false). Returns the
// server for chaining.
func (s *Server) WithTLSPosture(ps *threat.PostureStore) *Server {
	if ps != nil {
		s.tlsPostures = ps
	}
	return s
}

// handleTLSPosture serves GET /v1/tls/posture — the tenant's certificate
// inventory (latest analyzed posture per target, flagged findings + the
// verbatim certctl handoff payload). collector_running=false distinguishes
// "no HTTPS targets observed" from "the collector is not wired".
func (s *Server) handleTLSPosture(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.tlsPostures == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []threat.Posture{}, "collector_running": false})
		return nil
	}
	items := s.tlsPostures.List(tid)
	if items == nil {
		items = []threat.Posture{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "collector_running": true})
	return nil
}
