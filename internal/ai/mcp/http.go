// SPDX-License-Identifier: LicenseRef-probectl-TBD

package mcp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/httpbody"
)

// Authenticator resolves a bearer token to a principal (tenant + RBAC). The
// control-plane implementation maps a control-plane token to its tenant + the
// owning user's effective permissions.
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (*auth.Principal, error)
}

// HTTPHandler returns the MCP-over-HTTP handler — the network transport. It is
// POST-only JSON-RPC, authenticated with a Bearer token mapped to a tenant +
// RBAC. TLS is applied by the listener (the control plane wires it); this handler
// must never be exposed without TLS when network-reachable (CLAUDE.md §7
// guardrail 12). Treats the request body as untrusted input.
func (s *Server) HTTPHandler(authn Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		bearer := bearerToken(r)
		if bearer == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		p, err := authn.Authenticate(r.Context(), bearer)
		if err != nil || p == nil || p.TenantID == "" {
			if err != nil {
				s.log.Warn("mcp authentication failed", "error", err)
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		body, err := httpbody.ReadLimited(r.Body, 1<<20)
		if err != nil {
			if errors.Is(err, httpbody.ErrTooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		resp := s.Handle(r.Context(), p, body)
		if resp == nil {
			w.WriteHeader(http.StatusAccepted) // a notification — no body
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	})
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}
