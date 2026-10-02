// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// userAgentHash is a stable correlation digest of the request User-Agent. The
// raw UA can fingerprint a client, so the audit trail records a hash (AUD-10:
// "user agent hash"), not the string — enough to correlate a session's events
// without storing the identifying header.
func userAgentHash(ua string) string {
	if ua == "" {
		return ""
	}
	return "sha256:" + hex.EncodeToString(crypto.Hash([]byte(ua)))
}

// withRequestContext adds the "from where" of an audit event (AUD-10): the
// trusted-proxy-aware client IP, the user-agent hash, and the request id, plus
// a caller-supplied outcome. docs/audit.md promises "who did it, to what, from
// where, and when"; before this, route and auth events carried none of the
// "from where". It mutates and returns data (nil-safe).
func (s *Server) withRequestContext(r *http.Request, data map[string]any, outcome string) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	if ip := s.clientIP(r); ip != "" {
		data["ip"] = ip
	}
	if h := userAgentHash(r.UserAgent()); h != "" {
		data["user_agent"] = h
	}
	if id, ok := logging.RequestIDFromContext(r.Context()); ok && id != "" {
		data["request_id"] = id
	}
	if outcome != "" {
		data["outcome"] = outcome
	}
	return data
}

// auditActor returns a stable actor identity for the request's principal, used as
// the audit Event.Actor. It prefers the email, then the user id.
func auditActor(r *http.Request) string {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return "system"
	}
	switch {
	case p.Email != "":
		return p.Email
	case p.UserID != "":
		return p.UserID
	default:
		return "unknown"
	}
}

// recordAudit appends a tamper-evident audit event within the caller's current
// tenant transaction, so the audit row commits or rolls back atomically with the
// action it records (RLS confines it to the tenant). Call it inside an inTenant
// closure, after the audited mutation has succeeded.
func (s *Server) recordAudit(ctx context.Context, sc tenancy.Scope, r *http.Request, action, target string, data map[string]any) error {
	// AUD-10: explicit domain events (key rotate, role bind, agent revoke, token
	// create, …) carry the same "from where" as route events — ip, user-agent
	// hash, request id — plus outcome=success (they are appended after the
	// mutation succeeds). A caller that already set an outcome keeps it.
	outcome := "success"
	if data != nil {
		if _, ok := data["outcome"]; ok {
			outcome = ""
		}
	}
	data = s.withRequestContext(r, data, outcome)
	_, err := audit.TenantAppend(ctx, sc, auditActor(r), action, target, data)
	return err
}

// recordAuthFailure appends an auth.login_failed event for a rejected login
// (AUD-10). Authentication failures — a failed SSO exchange, a replayed/
// mismatched nonce, an unprovisioned or deactivated identity — were only
// slog'd, so a brute-force or token-replay left no tamper-evident trail. It is
// best-effort (a failed login must still return promptly even if the audit DB
// is momentarily unavailable; the per-IP/per-account limiters still count the
// failure) and records only a bounded, non-sensitive reason — never the token,
// code, or nonce. It writes to the tenant the login had already resolved to.
func (s *Server) recordAuthFailure(r *http.Request, tenantID, actor, reason string) {
	if s.pool == nil || tenantID == "" {
		return
	}
	if actor == "" {
		actor = "unknown"
	}
	data := s.withRequestContext(r, map[string]any{"reason": reason}, "failure")
	if err := tenancy.InTenant(tenancy.WithTenant(r.Context(), tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, e := audit.TenantAppend(ctx, sc, actor, "auth.login_failed", actor, data)
		return e
	}); err != nil {
		s.log.Warn("could not record auth-failure audit", "error", err.Error())
	}
}

// handleListAudit returns a page of the tenant's audit trail (admin audit
// search/export). It is gated by audit.read. Reading does not itself append an
// event (so admin-console polling doesn't grow the trail); deliberate config and
// data-access actions are what get recorded.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) error {
	after := int64Query(r, "after", 0)
	limit := intQuery(r, "limit", audit.DefaultExportPageSize)
	filter := audit.Filter{
		Actor:  stringQuery(r, "actor"),
		Action: stringQuery(r, "action"),
		Target: stringQuery(r, "target"),
	}

	var events []audit.Event
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		e, err := audit.ListFiltered(ctx, sc, after, limit, filter)
		events = e
		return err
	}); err != nil {
		return err
	}

	var next int64
	if n := len(events); n > 0 {
		next = events[n-1].Seq
	}
	// AUD-10: a deliberate export of the audit log is itself an auditable data
	// egress. Console polling (the common case) stays exempt so it does not grow
	// the chain it reads; an explicit `?export=true` fetch records exactly one
	// audit.export event, and — being an export — fails closed if it cannot.
	if stringQuery(r, "export") == "true" {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			_, e := audit.TenantAppend(ctx, sc, auditActor(r), "audit.export", "",
				s.withRequestContext(r, map[string]any{"count": len(events), "actor_filter": filter.Actor, "action_filter": filter.Action, "target_filter": filter.Target}, "success"))
			return e
		}); err != nil {
			return err
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events, "next": next})
	return nil
}

// handleVerifyAudit recomputes the tenant's audit chain and reports whether it is
// intact. An integrity finding is reported in the body (ok:false + detail), not
// as an error status — the request itself succeeded. Gated by audit.read.
func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) error {
	var integrity error
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		integrity = audit.TenantVerify(ctx, sc)
		return nil // an integrity finding is data, not a transaction failure
	}); err != nil {
		return err
	}

	// AUD-10: verify is intentionally NOT self-audited. Appending an event to the
	// very chain it checks would change that chain on every call — growing it on
	// each console poll and breaking the "verify is a pure read" invariant other
	// code relies on. The audited audit-log access is the explicit export in
	// handleListAudit (?export=true); verify stays a side-effect-free read.
	body := map[string]any{"ok": integrity == nil}
	if integrity != nil {
		body["detail"] = integrity.Error()
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

// int64Query reads a non-negative int64 query parameter, falling back to def.
func int64Query(r *http.Request, name string, def int64) int64 {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// intQuery reads a non-negative int query parameter, falling back to def.
func intQuery(r *http.Request, name string, def int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// stringQuery reads a trimmed, bounded query filter. Empty means no filter.
func stringQuery(r *http.Request, name string) string {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if len(v) > 256 {
		return v[:256]
	}
	return v
}
