// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
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
	// AUTHZ-25: the detailed readiness posture — cluster role/epoch + the raw
	// writer-probe reason, audit-retention + alerting health, and the volatile
	// store list — is operator reconnaissance. It is returned ONLY to an
	// authenticated caller; an anonymous probe (the load balancer / uptime
	// check) gets status only, so retention/alerting/cluster posture never leaks
	// without credentials. Mirrors the /version hardening (SEC-008). The HTTP
	// status code is identical for every caller, so probes keep working.
	authed := auth.PrincipalFrom(r.Context()) != nil

	if s.draining.Load() {
		return apierror.Unavailable("draining")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if s.pinger != nil {
		if err := s.pinger.Ping(ctx); err != nil {
			s.log.Debug("readiness: database not ready", "error", err.Error())
			if !authed {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready"})
				return nil
			}
			// DPR-100: the cluster view rides the not-ready answer for an
			// authenticated operator (or a failover drill) diagnosing a lost
			// writer — writes_usable / the writer's role / the epoch exactly
			// while the database is unreachable, not a bare error envelope.
			reqID, _ := logging.RequestIDFromContext(r.Context())
			body := map[string]any{
				"status": "not_ready",
				"error":  errorDetail{Code: "unavailable", Message: "database not ready", RequestID: reqID},
			}
			if cs := s.clusterStatus(); cs != nil {
				body["cluster"] = cs
			}
			writeJSON(w, http.StatusServiceUnavailable, body)
			return nil
		}
	}
	if !authed {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
		return nil
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
	// PLAT-01/RTO-04: the node stays READY (reads/writes work) but surfaces any
	// memory-backed telemetry planes so an operator or automation sees that the
	// deployment loses history on restart. Durable deployments omit the field.
	if s.cfg != nil {
		if volatile := s.cfg.VolatileStores(); len(volatile) > 0 {
			body["volatile_stores"] = volatile
		}
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

// requireMetricsScrape authorizes the /metrics exposition (AUTHZ-25). The
// Prometheus text carries build/commit provenance and pipeline counters — a
// fingerprinting surface that must not answer an anonymous caller on the public
// listener. A legitimate ServiceMonitor scrapes with the configured
// PROBECTL_METRICS_SCRAPE_TOKEN as a bearer; a local dev build is trusted
// (loopback-bound and acked, like the /version SEC-008 carve-out). Everything
// else gets 401 — fail closed.
func (s *Server) requireMetricsScrape(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.metricsScrapeAuthorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="probectl-metrics"`)
		writeError(w, r, apierror.Unauthorized("metrics scrape requires the configured scrape token (PROBECTL_METRICS_SCRAPE_TOKEN)"))
	})
}

// metricsScrapeAuthorized reports whether this request may read /metrics. It is
// the one place the scrape policy lives (requireMetricsScrape delegates here),
// so the regression test can drive it directly.
func (s *Server) metricsScrapeAuthorized(r *http.Request) bool {
	if s.cfg == nil {
		return false
	}
	// Local dev evaluation is loopback-bound and acked (RED-001/SEC-001); treat
	// it as trusted, mirroring the /version dev carve-out (SEC-008).
	if s.cfg.AuthMode == "dev" && DevModeAvailable() {
		return true
	}
	token := strings.TrimSpace(s.cfg.MetricsScrapeToken)
	if token == "" {
		// No scrape credential configured on a non-dev deployment → fail closed.
		return false
	}
	presented, _ := bearerTokenFromRequest(r)
	if presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1
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
