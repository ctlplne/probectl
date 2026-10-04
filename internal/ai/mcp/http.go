// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/httpbody"
)

// rpcErrorCode returns the JSON-RPC error code of a single serialized response,
// or 0 when the body is a success result, a batch, or not decodable. It lets the
// HTTP transport reflect a rate-limited response as HTTP 429 (RTA-05) without
// changing the JSON-RPC body.
func rpcErrorCode(resp []byte) int {
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp, &r); err != nil || r.Error == nil {
		return 0
	}
	return r.Error.Code
}

// Authenticator resolves a bearer token to a principal (tenant + RBAC + ABAC
// subject attributes). The control-plane implementation maps a control-plane
// token to its tenant and the owning user's effective authorization state.
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (*auth.Principal, error)
}

// ErrForbidden marks an Authenticate failure that is a policy refusal rather
// than a bad token — a suspended/offboarded tenant or an unmet MFA requirement
// (AUTHZ-12). The handler maps it to 403, matching the /v1 edge; every other
// authentication error maps to 401.
var ErrForbidden = errors.New("mcp: forbidden")

// HTTPHandler returns the MCP-over-HTTP handler — the network transport. It is
// POST-only JSON-RPC, authenticated with a Bearer token mapped to a tenant +
// RBAC. TLS is applied by the listener (the control plane wires it); this handler
// must never be exposed without TLS when network-reachable (docs/guardrails.md
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
			// AUTHZ-12: a policy refusal (suspended/offboarded tenant, MFA
			// required) is 403 like /v1; a bad/expired/disabled token is 401.
			if errors.Is(err, ErrForbidden) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
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
		// RTA-05: a rate-limited response also carries HTTP 429 + Retry-After, so
		// a client's standard transport-level backoff triggers without having to
		// parse the JSON-RPC body. Other responses keep HTTP 200 (JSON-RPC
		// carries their status in the body, the protocol's contract).
		if rpcErrorCode(resp) == codeRateLimited {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
		}
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
