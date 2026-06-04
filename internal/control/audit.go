package control

import (
	"context"
	"net/http"
	"strconv"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

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
	_, err := audit.TenantAppend(ctx, sc, auditActor(r), action, target, data)
	return err
}

// handleListAudit returns a page of the tenant's audit trail (admin audit
// search/export). It is gated by audit.read. Reading does not itself append an
// event (so admin-console polling doesn't grow the trail); deliberate config and
// data-access actions are what get recorded.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) error {
	after := int64Query(r, "after", 0)
	limit := intQuery(r, "limit", audit.DefaultExportPageSize)

	var events []audit.Event
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		e, err := audit.List(ctx, sc, after, limit)
		events = e
		return err
	}); err != nil {
		return err
	}

	var next int64
	if n := len(events); n > 0 {
		next = events[n-1].Seq
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
