// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
)

// chain wraps h with the given middleware. The first middleware is outermost.
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// contentSecurityPolicy is the strict policy set on every response (U-023,
// docs/guardrails.md G7-12). The UI bundle is fully same-origin (external
// Vite-built JS/CSS, CSS modules, hand-rolled SVG viz, fetch to /v1 — no
// inline <script>/<style>, no third-party origins, sovereignty guardrail 11),
// so nothing needs 'unsafe-inline' or a nonce. img-src allows data: URIs
// (inline icons/favicons); frame-ancestors 'none' (plus X-Frame-Options DENY
// for legacy browsers) forbids all framing — clickjacking is structurally off.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; " +
	"style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; object-src 'none'; base-uri 'self'; " +
	"form-action 'self'; frame-ancestors 'none'"

// permissionsPolicy denies the powerful browser features the dashboard never
// uses (SEC-006). An empty allowlist () denies the feature for ALL origins
// (including self); fullscreen is allowed for self (the topology/path hero
// views). interest-cohort=() opts out of FLoC.
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), " +
	"display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), " +
	"gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), " +
	"interest-cohort=()"

// securityHeaders sets baseline response headers. HSTS is set now (honored by
// browsers only over HTTPS) so the posture is correct once TLS terminates at the
// ingress / lands in S3 (docs/guardrails.md G7-12). CSP + X-Frame-Options
// apply to every UI/API response (U-023).
func securityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
	var hsts string
	if cfg.HSTSEnabled {
		hsts = fmt.Sprintf("max-age=%d; includeSubDomains", int(cfg.HSTSMaxAge.Seconds()))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Content-Security-Policy", contentSecurityPolicy)
			h.Set("X-Frame-Options", "DENY")
			// SEC-006: don't leak URLs to cross-origin navigations, and deny
			// powerful browser features the dashboard never uses.
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Permissions-Policy", permissionsPolicy)
			if hsts != "" {
				h.Set("Strict-Transport-Security", hsts)
			}
			// WEB-16: authenticated API surfaces carry tenant data that must not
			// be cached by the browser or a shared proxy. Static UI assets keep
			// their cacheability (served under /ui/ by the webui handler, which
			// sets no-store on the app-shell HTML itself).
			if noStorePath(r.URL.Path) {
				h.Set("Cache-Control", "no-store")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// noStorePath reports whether a request path serves authenticated/sensitive
// responses that must be Cache-Control: no-store (WEB-16). Public, cacheable
// surfaces (the /ui bundle, health/version/branding, the RUM ingest) are not
// listed, so they keep their own caching.
func noStorePath(p string) bool {
	return p == "/v1" || strings.HasPrefix(p, "/v1/") ||
		strings.HasPrefix(p, "/auth/") ||
		strings.HasPrefix(p, "/scim/") ||
		strings.HasPrefix(p, "/provider/")
}

// requestContext assigns a request correlation ID (honoring an inbound
// X-Request-Id), attaches a request-scoped logger to the context, and echoes the
// ID back. This is the seam where S2 attaches the resolved tenant to the context
// (internal/tenancy): the rest of the chain and every handler already operate on
// ctx, so nothing needs refactoring to become tenant-aware (F50).
func requestContext(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// WEB-20: an inbound X-Request-Id is honored only when it is a sane
			// correlation id — at most 128 chars of [A-Za-z0-9-]. A client must
			// not be able to forge or collide ids, nor inflate log volume with an
			// 8 KB value echoed into every log line; anything off-shape is
			// replaced with a server-generated id.
			id := r.Header.Get("X-Request-Id")
			if !validRequestID(id) {
				id = newRequestID()
			}
			ctx := logging.WithRequestID(r.Context(), id)
			ctx = logging.WithLogger(ctx, base.With("request_id", id))
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// accessLog records one structured line per request. Health/readiness probes log
// at debug to avoid flooding logs under frequent polling.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" {
			level = slog.LevelDebug
		}
		logging.FromContext(r.Context()).Log(r.Context(), level, "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.Status(),
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
			"client", s.clientIP(r),
		)
	})
}

// recoverer turns a panic in any inner handler into a 500 (never crash a
// production path — CONTRIBUTING.md).
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logging.FromContext(r.Context()).Error("panic recovered",
					"panic", fmt.Sprint(rec), "path", r.URL.Path)
				writeError(w, r, apierror.Internal("internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the status code and byte count for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

func (s *statusRecorder) Status() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

// Unwrap exposes the wrapped ResponseWriter so http.NewResponseController can
// reach the underlying connection (WEB-04). Without it, SetWriteDeadline (used
// by extendWriteDeadline to lift the global WriteTimeout for long-running
// responses) returns ErrNotSupported and the extension is a silent no-op, since
// every request is wrapped in this access-log recorder.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// newRequestID returns a random 128-bit hex correlation ID. This is a
// non-security trace identifier, so a non-cryptographic source is intentional
// (cryptographic randomness routes through internal/crypto from S3).
func newRequestID() string {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], rand.Uint64())
	binary.LittleEndian.PutUint64(b[8:16], rand.Uint64())
	return hex.EncodeToString(b[:])
}

// validRequestID reports whether an inbound X-Request-Id is a sane correlation
// id worth honoring: 1..128 chars of [A-Za-z0-9-] (WEB-20). Anything longer or
// with other characters is a forgery/collision/log-inflation vector and is
// replaced with a freshly generated id.
func validRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}
