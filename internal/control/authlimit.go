// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Auth-endpoint brute-force protection (U-024): /auth/login and
// /auth/callback are throttled per source IP, and the callback additionally
// per account once the IdP exchange identifies one. Lockouts back off
// exponentially and are audited.

// newAuthLimiter builds the limiter from config (zero values = the limiter's
// safe defaults: 5 failures / 1m window / 1m lockout doubling to 1h) and
// wires the lockout audit seam.
func (s *Server) newAuthLimiter(cfg *config.Config) *auth.Limiter {
	l := auth.NewLimiter(cfg.AuthRateMaxFailures, cfg.AuthRateWindow, cfg.AuthRateLockout)
	l.OnLockout = func(key string, failures int, lockout time.Duration) {
		// Loud either way; account lockouts also land in the tenant's
		// tamper-evident audit stream (guardrail 7).
		s.log.Warn("auth lockout", "key", key, "failures", failures, "lockout", lockout.String())
		tid, email, ok := splitAcctKey(key)
		if !ok || s.pool == nil {
			return
		}
		if err := s.inTenantID(context.Background(), tid, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := audit.TenantAppend(ctx, sc, email, "auth.lockout", email, map[string]any{
				"failures": failures, "lockout": lockout.String(), "dimension": "account",
			})
			return err
		}); err != nil {
			// CODE-002: surface a failed lockout-audit write (the lockout already
			// applied; the audit record must not vanish silently).
			s.log.Warn("failed to persist auth.lockout audit record", "tenant_id", tid, "error", err.Error())
		}
	}
	return l
}

func acctKey(tenantID, email string) string { return "acct:" + tenantID + ":" + email }

func splitAcctKey(key string) (tenantID, email string, ok bool) {
	rest, found := strings.CutPrefix(key, "acct:")
	if !found {
		return "", "", false
	}
	tenantID, email, found = strings.Cut(rest, ":")
	return tenantID, email, found && tenantID != "" && email != ""
}

// clientIP is the throttle key source: the transport RemoteAddr. Forwarded
// headers are deliberately NOT trusted (spoofable); a fronting ingress that
// should count real client IPs must rewrite the connection source (e.g.
// PROXY protocol) rather than a header.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// throttleAuth wraps an auth endpoint with the per-IP attempt gate. A locked
// source gets 429 + Retry-After without the handler running.
func (s *Server) throttleAuth(h apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		ok, retry := s.authLimiter.Attempt("ip:" + clientIP(r))
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds()+0.5)))
			return apierror.RateLimited("too many authentication attempts — retry later")
		}
		return h(w, r)
	}
}

// checkAccountThrottle gates the post-exchange account dimension: a locked
// account is refused even when the IdP exchange succeeded (stolen-code
// replay or an IdP-side loop keeps hitting the wall here).
func (s *Server) checkAccountThrottle(w http.ResponseWriter, tenantID, email string) error {
	ok, retry := s.authLimiter.Allow(acctKey(tenantID, email))
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds()+0.5)))
		return apierror.RateLimited("account temporarily locked — retry later")
	}
	return nil
}
