// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/version"
)

// handleHealthz is the liveness probe: 200 while the process is serving.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

// handleReadyz is the readiness probe: 200 when dependencies (the database) are
// reachable, otherwise 503 via the Unavailable domain error. During a graceful
// shutdown it reports 503 "draining" FIRST (before in-flight requests finish), so
// a load balancer stops routing new traffic to this replica — the key to a
// zero-downtime rolling upgrade (S34): drain, then exit.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) error {
	if s.draining.Load() {
		return apierror.Unavailable("draining")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if s.pinger != nil {
		if err := s.pinger.Ping(ctx); err != nil {
			// DPR-100: the cluster view rides the not-ready answer too. An
			// operator (or a failover drill) diagnosing a lost writer needs
			// writes_usable / the writer's role / the epoch exactly while the
			// database is unreachable, not a bare error envelope.
			reqID, _ := logging.RequestIDFromContext(r.Context())
			body := map[string]any{
				"status": "not_ready",
				"error":  errorDetail{Code: "unavailable", Message: "database not ready", RequestID: reqID},
			}
			if cs := s.clusterStatus(); cs != nil {
				body["cluster"] = cs
			}
			s.log.Debug("readiness: database not ready", "error", err.Error())
			writeJSON(w, http.StatusServiceUnavailable, body)
			return nil
		}
	}
	// Multi-region (S-EE2): the cluster view rides /readyz — region, the
	// writer's role, whether writes are usable, and replica lag. The node
	// stays READY (200) for reads even when writes are fenced (a failover in
	// progress is not unreadiness — the region still serves traffic); the
	// writes_usable flag tells operators/automation when writes paused.
	body := map[string]any{
		"status":          "ready",
		"audit_retention": s.auditRetentionHealth(),
		"alerting":        s.alertingHealth(),
	}
	if cs := s.clusterStatus(); cs != nil {
		body["cluster"] = cs
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

// handleVersion reports build metadata — an operational/observability endpoint.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) error {
	// SEC-008: build/commit/Go/OS detail is reconnaissance — full detail only
	// for authenticated callers outside dev mode; anonymous gets the service
	// name (load balancers and uptime checks keep working).
	if s.cfg.AuthMode != "dev" && s.resolvePrincipal(r) == nil {
		writeJSON(w, http.StatusOK, map[string]string{"service": "probectl"})
		return nil
	}
	writeJSON(w, http.StatusOK, version.Get())
	return nil
}
