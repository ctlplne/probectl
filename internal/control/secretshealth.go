// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

// Secret-backend health surface (S41, F31): GET /v1/secrets/health reports
// per-backend operational state — configured schemes, resolve/failure
// counters, live lease counts, and the last (redacted) error — so operators
// can see credential-resolution health in the Admin surface without any
// secret material ever crossing the API. The honesty flag follows the M-FE
// pattern: resolver_running=false distinguishes an unwired resolver from a
// healthy-but-idle one.

import (
	"net/http"

	"github.com/ctlplne/probectl/internal/secrets"
)

// SecretsHealthSource is the read-side seam (*secrets.Resolver satisfies it).
type SecretsHealthSource interface {
	Health() []secrets.BackendHealth
}

// WithSecrets attaches the secrets resolver backing /v1/secrets/health.
// nil is a no-op (the endpoint reports resolver_running=false). Returns the
// server for chaining.
func (s *Server) WithSecrets(src SecretsHealthSource) *Server {
	if src != nil {
		s.secretsHealth = src
	}
	return s
}

type secretsHealthResponse struct {
	ResolverRunning bool                    `json:"resolver_running"`
	Backends        []secrets.BackendHealth `json:"backends"`
}

// handleSecretsHealth serves GET /v1/secrets/health. Health snapshots are
// process-wide operational metadata (never tenant telemetry, never secret
// material); access still requires an authenticated principal with directory
// read (the admin-surface permission, enforced by the route table).
func (s *Server) handleSecretsHealth(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	resp := secretsHealthResponse{Backends: []secrets.BackendHealth{}}
	if s.secretsHealth != nil {
		resp.ResolverRunning = true
		resp.Backends = s.secretsHealth.Health()
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}
