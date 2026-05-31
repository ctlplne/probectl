package control

import (
	"context"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/version"
)

// handleHealthz is the liveness probe: 200 while the process is serving.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

// handleReadyz is the readiness probe: 200 when dependencies (the database) are
// reachable, otherwise 503 via the Unavailable domain error.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if s.pinger != nil {
		if err := s.pinger.Ping(ctx); err != nil {
			return apierror.Unavailable("database not ready").Wrap(err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	return nil
}

// handleVersion reports build metadata — an operational/observability endpoint.
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, version.Get())
	return nil
}
