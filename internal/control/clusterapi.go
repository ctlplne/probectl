// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/cluster"
)

// Multi-region / active-active HA (S-EE2). The cluster manager owns the
// split-brain write fence and the region/health status. There is NO new
// tenant-facing route — the sprint surfaces this "via existing health/status"
// (/readyz carries the cluster view; the write fence rides the middleware
// chain). Reads keep serving during a failover; only mutating requests fence.

// WithCluster attaches the cluster manager (multi-region deployments). nil =
// single-region: the write fence is inert and /readyz omits cluster state.
func (s *Server) WithCluster(m *cluster.Manager) *Server {
	if m != nil {
		s.cluster = m
	}
	return s
}

// writeFence fails mutating API requests closed (503, retryable) when the
// writer endpoint is not provably the current primary — a standby, a stale
// ex-primary, or unreachable. This is the app-layer split-brain guard: during
// a failover the region keeps serving reads while writes pause until the
// promotion settles, rather than risk a write to the wrong primary. Telemetry
// ingest (the bus consumers) is unaffected — it never crosses this chain.
func (s *Server) writeFence(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cluster != nil && isMutating(r.Method) && !fenceExempt(r.URL.Path) {
			if ok, reason := s.cluster.WriterUsable(); !ok {
				w.Header().Set("Retry-After", "2")
				writeError(w, r, apierror.Unavailable("writer unavailable: "+reason).WithCode("writer_unavailable"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// fenceExempt are mutating paths that must work even when the writer is down:
// authentication (so operators can log in to run the failover) and logout.
// These do not write tenant/config state on the critical failover path.
func fenceExempt(path string) bool {
	return strings.HasPrefix(path, "/auth/") || path == "/v1/auth/logout"
}

// clusterStatus returns the cluster view for /readyz, or nil in a
// single-region deployment.
func (s *Server) clusterStatus() *cluster.Status {
	if s.cluster == nil {
		return nil
	}
	st := s.cluster.Status()
	return &st
}
