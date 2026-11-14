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
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/httpbody"
	"github.com/ctlplne/probectl/internal/tenancy"
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
// authentication error maps to 401, except typed unavailable failures (503).
var ErrForbidden = errors.New("mcp: forbidden")

// HTTPHandler returns the MCP-over-HTTP handler — the network transport. It is
// POST-only JSON-RPC, authenticated with a Bearer token mapped to a tenant +
// RBAC. TLS is applied by the listener (the control plane wires it); this handler
// must never be exposed without TLS when network-reachable (docs/guardrails.md
// guardrail 12). Treats the request body as untrusted input.
func (s *Server) HTTPHandler(authn Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.httpWorkBudget.Validate() != nil || s.legacyHTTP == nil {
			http.Error(w, "HTTP work policy is unavailable", http.StatusServiceUnavailable)
			return
		}
		if s.httpOriginsInvalid {
			http.Error(w, "HTTP origin policy is unavailable", http.StatusServiceUnavailable)
			return
		}
		if !s.allowsHTTPOrigin(r) {
			http.Error(w, "origin is not allowed", http.StatusForbidden)
			return
		}
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
			s.legacyHTTP.cancelCredential(bearer)
			if err != nil {
				s.log.Warn("mcp authentication failed", "error_class", ErrorClass(err))
			}
			// AUTHZ-12: a policy refusal (suspended/offboarded tenant, MFA
			// required) is 403 like /v1; a bad/expired/disabled token is 401.
			if errors.Is(err, ErrForbidden) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if authenticationUnavailable(err) {
				http.Error(w, "authentication policy is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			// D-62: a quarantined tenant is refused with the actionable cause,
			// as a retry-later 503 (the token itself is valid).
			var quarantined *tenancy.QuarantinedError
			if errors.As(err, &quarantined) {
				http.Error(w, quarantined.TenantMessage(), http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// A listener's short default must not cut off an authenticated,
		// admitted large native result before its operator-owned work budget.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.httpWorkBudget.Timeout).Add(httpResponseCloseGrace))
		limit := int64(1 << 20)
		if s.nativeEnabled {
			limit = int64(s.nativeRequestBytes())
		}
		body, err := httpbody.ReadLimited(r.Body, limit)
		if err != nil {
			if errors.Is(err, httpbody.ErrTooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if len(body) > 1<<20 && !s.isNativeCall(body) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		versionValues := headerValues(r.Header, "MCP-Protocol-Version")
		version, _ := singleHeaderValue(versionValues)
		req, failure := s.decodeRPC(body, modernVersionHeader(version) || len(versionValues) > 1)
		if !req.protocol.modern && version == legacyProtocolVersion {
			req, failure = decodeLegacy2025RPCBudget(body, s.nativeRequestBytes())
		}
		if !req.protocol.modern && req.protocol.version == legacyProtocolVersion {
			if notice, _ := stdioNotification(body); notice && (req.Method == notificationCanceled || boundedJSONObjectSyntax(body, 4<<20, false) == nil) {
				failure = nil // malformed cancellation is ignored, valid notices are accepted
			}
			if failure == nil {
				failure = validateLegacyHTTP(r, req)
			}
			if failure != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(marshal(s.prepareResponse(req, failure)))
				return
			}
			s.serveLegacyHTTP(w, r, authn, p, bearer, body, req)
			return
		}
		if failure == nil && req.protocol.modern {
			failure = validateModernHTTP(r, req)
		}
		if failure != nil {
			w.Header().Set("Content-Type", "application/json")
			if req.protocol.modern {
				w.WriteHeader(modernHTTPStatus(failure.Error.Code))
			}
			_, _ = w.Write(marshal(s.prepareResponse(req, failure)))
			return
		}
		p = principalSnapshot(p)
		requestCtx := withCredentialPublicationGuard(r.Context(), p, func(ctx context.Context) (*auth.Principal, error) {
			return authn.Authenticate(ctx, bearer)
		})
		streaming := false
		if req.protocol.modern && len(req.protocol.progress) > 0 {
			req.protocol.frameReserve = 8
			requestCtx = withProgressEmitter(requestCtx, func(stage int) error {
				if err := r.Context().Err(); err != nil {
					return err
				}
				message, err := progressMessage(req.protocol.progress, stage)
				if err != nil {
					return err
				}
				if !streaming {
					w.Header().Set("Content-Type", "text/event-stream")
					w.Header().Set("Cache-Control", "no-store")
					w.Header().Set("X-Accel-Buffering", "no")
					streaming = true
				}
				if err := writeSSE(w, message); err != nil {
					return err
				}
				return http.NewResponseController(w).Flush()
			})
		}
		resp, code := s.handleRequestWithCode(requestCtx, p, req, body)
		if req.protocol.modern && r.Context().Err() != nil {
			return
		}
		if streaming {
			if resp != nil {
				_ = writeSSE(w, resp)
				_ = http.NewResponseController(w).Flush()
			}
			return
		}
		if resp == nil {
			w.WriteHeader(http.StatusAccepted) // a notification — no body
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// RTA-05: a rate-limited response also carries HTTP 429 + Retry-After, so
		// a client's standard transport-level backoff triggers without having to
		// parse the JSON-RPC body. Other responses keep HTTP 200 (JSON-RPC
		// carries their status in the body, the protocol's contract).
		if code == codeRateLimited || code == codeModernRateLimited {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
		} else if req.protocol.modern {
			w.WriteHeader(modernHTTPStatus(code))
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
