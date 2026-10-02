// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestAuditCoverageAUD10 is the AUD-10 regression: authentication failures and
// logouts are now audited; a deliberate audit-log export is recorded; and every
// route-level access.* event (and the auth events) carry the "from where" —
// ip, user_agent (hashed), request_id — plus an outcome. docs/audit.md promises
// "who did it, to what, from where, and when"; before this the route events had
// no ip/ua/request_id/outcome, failed logins and logouts were only slog'd, and
// GET /v1/audit was wholly exempt.
func TestAuditCoverageAUD10(t *testing.T) {
	const ua = "AUD10-UserAgent/9.9"
	email := fmt.Sprintf("aud10-%d@example.com", time.Now().UnixNano())
	ident := auth.Identity{Subject: fmt.Sprintf("sub-%d", time.Now().UnixNano()), Email: email, DisplayName: "AUD10"}
	srv, db, provider := setupSessionAPIWithProvider(t, ident)
	h := srv.Handler()
	ctx := context.Background()
	tid := tenancy.DefaultTenantID.String()

	// events returns this actor's audit events for an action (scoped by the
	// unique email so the shared default tenant's other rows don't interfere).
	events := func(t *testing.T, action string) []map[string]any {
		t.Helper()
		rows, err := db.Pool().Query(ctx,
			`SELECT data::text FROM audit_events WHERE tenant_id = $1::uuid AND action = $2 AND actor = $3 ORDER BY seq`,
			tid, action, email)
		if err != nil {
			t.Fatalf("query %s: %v", action, err)
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				t.Fatalf("scan: %v", err)
			}
			m := map[string]any{}
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				t.Fatalf("unmarshal %s data: %v", action, err)
			}
			out = append(out, m)
		}
		return out
	}
	hasContext := func(t *testing.T, action string, m map[string]any, wantOutcome string) {
		t.Helper()
		for _, f := range []string{"ip", "user_agent", "request_id", "outcome"} {
			if v, ok := m[f]; !ok || v == "" {
				t.Errorf("AUD-10: %s event is missing the %q field (data=%v)", action, f, m)
			}
		}
		if m["outcome"] != wantOutcome {
			t.Errorf("AUD-10: %s outcome = %v, want %q", action, m["outcome"], wantOutcome)
		}
		if uaVal, _ := m["user_agent"].(string); uaVal == ua {
			t.Errorf("AUD-10: %s stored the raw user agent instead of a hash", action)
		}
	}

	// doLogin runs GET /auth/login then the callback, returning the callback
	// recorder and the session cookie (nil on a failed login).
	doLogin := func(t *testing.T) (*httptest.ResponseRecorder, *http.Cookie) {
		t.Helper()
		loginReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		loginReq.Header.Set("User-Agent", ua)
		login := httptest.NewRecorder()
		h.ServeHTTP(login, loginReq)
		state := findCookie(login.Result().Cookies(), oauthStateCookie)
		tenantCk := findCookie(login.Result().Cookies(), oauthTenantCookie)
		nonceCk := findCookie(login.Result().Cookies(), oauthNonceCookie)
		pkceCk := findCookie(login.Result().Cookies(), oauthPKCECookie)
		cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state.Value, nil)
		cb.Header.Set("User-Agent", ua)
		for _, c := range []*http.Cookie{state, tenantCk, nonceCk, pkceCk} {
			if c != nil {
				cb.AddCookie(c)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, cb)
		return rec, findCookie(rec.Result().Cookies(), auth.SessionCookie)
	}

	// 1. FAILED LOGIN — a replayed/mismatched nonce must be audited.
	provider.wrongNonce = true
	if rec, _ := doLogin(t); rec.Code == http.StatusFound {
		t.Fatalf("expected the nonce-mismatch login to fail, got 302")
	}
	failed := events(t, "auth.login_failed")
	if len(failed) != 1 {
		t.Fatalf("AUD-10: a failed login must be audited exactly once, got %d", len(failed))
	}
	hasContext(t, "auth.login_failed", failed[0], "failure")
	if failed[0]["reason"] != "oidc_nonce_mismatch" {
		t.Errorf("AUD-10: failed-login reason = %v, want oidc_nonce_mismatch", failed[0]["reason"])
	}

	// 2. SUCCESSFUL LOGIN — enriched with the from-where + outcome=success.
	provider.wrongNonce = false
	_, sess := doLogin(t)
	if sess == nil {
		t.Fatal("expected a session cookie after a successful login")
	}
	ok := events(t, "auth.login")
	if len(ok) != 1 {
		t.Fatalf("AUD-10: expected one auth.login event, got %d", len(ok))
	}
	hasContext(t, "auth.login", ok[0], "success")

	// The authenticated session rotates its token on every request, so thread
	// (and refresh) the session cookie between calls.
	send := func(t *testing.T, method, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("User-Agent", ua)
		req.AddCookie(sess)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if n := findCookie(rec.Result().Cookies(), auth.SessionCookie); n != nil && n.Value != "" {
			sess = n
		}
		return rec
	}

	// A viewer-readable, audited GET produces a route-level access.* event that
	// must also carry the from-where fields.
	var userID string
	if err := db.Pool().QueryRow(ctx, `SELECT id::text FROM users WHERE tenant_id=$1::uuid AND lower(email)=lower($2)`, tid, email).Scan(&userID); err != nil {
		t.Fatalf("resolve user: %v", err)
	}
	bindRole(t, db, userID, "viewer")
	if getRec := send(t, http.MethodGet, "/v1/incidents"); getRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/incidents as viewer: want 200, got %d: %s", getRec.Code, getRec.Body)
	}
	access := events(t, "access.read.incidents")
	if len(access) == 0 {
		t.Fatalf("AUD-10: GET /v1/incidents produced no access.read.incidents audit event")
	}
	hasContext(t, "access.read.incidents", access[len(access)-1], "authorized")

	// 3. AUDIT-LOG EXPORT — an explicit export is recorded once. (viewer holds
	// audit.read via its *.read grant.)
	if exportRec := send(t, http.MethodGet, "/v1/audit?export=true"); exportRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit?export=true: want 200, got %d: %s", exportRec.Code, exportRec.Body)
	}
	exp := events(t, "audit.export")
	if len(exp) != 1 {
		t.Fatalf("AUD-10: an audit export must be recorded exactly once, got %d", len(exp))
	}
	hasContext(t, "audit.export", exp[0], "success")

	// 4. LOGOUT — must be audited.
	if logoutRec := send(t, http.MethodPost, "/auth/logout"); logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout: want 204, got %d: %s", logoutRec.Code, logoutRec.Body)
	}
	lo := events(t, "auth.logout")
	if len(lo) != 1 {
		t.Fatalf("AUD-10: a logout must be audited exactly once, got %d", len(lo))
	}
	hasContext(t, "auth.logout", lo[0], "success")
}
