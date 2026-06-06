package control

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
)

// chain wraps h with the given middleware. The first middleware is outermost.
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// contentSecurityPolicy is the strict policy set on every response (U-023,
// CLAUDE.md §7 guardrail 12). The UI bundle is fully same-origin (external
// Vite-built JS/CSS, CSS modules, hand-rolled SVG viz, fetch to /v1 — no
// inline <script>/<style>, no third-party origins, sovereignty guardrail 11),
// so nothing needs 'unsafe-inline' or a nonce. img-src allows data: URIs
// (inline icons/favicons); frame-ancestors 'none' (plus X-Frame-Options DENY
// for legacy browsers) forbids all framing — clickjacking is structurally off.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; " +
	"style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; object-src 'none'; base-uri 'self'; " +
	"form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets baseline response headers. HSTS is set now (honored by
// browsers only over HTTPS) so the posture is correct once TLS terminates at the
// ingress / lands in S3 (CLAUDE.md §7 guardrail 12). CSP + X-Frame-Options
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
			if hsts != "" {
				h.Set("Strict-Transport-Security", hsts)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requestContext assigns a request correlation ID (honoring an inbound
// X-Request-Id), attaches a request-scoped logger to the context, and echoes the
// ID back. This is the seam where S2 attaches the resolved tenant to the context
// (internal/tenancy): the rest of the chain and every handler already operate on
// ctx, so nothing needs refactoring to become tenant-aware (F50).
func requestContext(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-Id")
			if id == "" {
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
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			level = slog.LevelDebug
		}
		logging.FromContext(r.Context()).Log(r.Context(), level, "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.Status(),
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// recoverer turns a panic in any inner handler into a 500 (never crash a
// production path — CLAUDE.md §6).
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

// newRequestID returns a random 128-bit hex correlation ID. This is a
// non-security trace identifier, so a non-cryptographic source is intentional
// (cryptographic randomness routes through internal/crypto from S3).
func newRequestID() string {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], rand.Uint64())
	binary.LittleEndian.PutUint64(b[8:16], rand.Uint64())
	return hex.EncodeToString(b[:])
}
