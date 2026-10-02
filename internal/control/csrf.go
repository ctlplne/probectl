// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

// csrfGuard refuses a cross-origin, cookie-authenticated state-changing request
// (AUTHZ-05). The session cookie is SameSite=Lax, which still rides same-site
// requests — a sibling subdomain of the deployment's registrable domain (or an
// XSS on one) can otherwise drive a logged-in user's browser to POST/PUT/PATCH/
// DELETE. A mutation carrying the ambient session cookie must therefore come
// from the deployment's own origin. Bearer-token API calls carry no ambient
// cookie and are unaffected (CORS governs them); the request-body Content-Type
// check in decodeJSON closes the preflight-free form vector. This is enforced
// at the middleware edge so it also covers the provider break-glass consent.
func (s *Server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutating(r.Method) && cookieAuthenticated(r) {
			origin := r.Header.Get("Origin")
			if origin != "" && !sameOriginHost(origin, r.Host) {
				writeError(w, r, apierror.Forbidden("cross-origin state-changing request refused").WithCode("cross_origin_denied"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// cookieAuthenticated reports whether the request is driven by an ambient
// session cookie rather than an explicit bearer token. A bearer token takes
// precedence in resolution and is not ambient, so a request that presents one
// is treated as token-authenticated (no CSRF exposure).
//
// BOTH privilege domains' cookies count (AUTHZ-05): the tenant session and the
// provider-operator session. The operator cookie is SameSite=Strict, but Strict
// still rides same-site requests, so a sibling subdomain of the MSP's own domain
// (the finding's threat model) could otherwise drive an operator's browser to
// suspend/offboard/erase a tenant or approve a break-glass grant. The guard must
// see the operator cookie or those mutations get no origin check at all.
func cookieAuthenticated(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return false
	}
	for _, name := range []string{auth.SessionCookie, auth.ProviderSessionCookie} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return true
		}
	}
	return false
}

// sameOriginHost reports whether an Origin header names the same host:port the
// request arrived on. Host-only (scheme-agnostic) comparison is robust behind a
// TLS-terminating ingress and still rejects any sibling subdomain. An
// unparseable or host-less Origin on a cookie mutation is refused.
func sameOriginHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}
