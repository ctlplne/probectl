// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
)

// INV-03/RT-02 end to end over HTTP: the /v1/api-tokens surface creates, lists
// and revokes tokens; a token past its expiry is a 401; a read-only token is
// 403 on a write route but 200 on a read route; revoking one token leaves the
// user's others working; and create/first-use/revoke are all written to the
// tenant audit chain.
func TestAPITokenLifecycleOverHTTP(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	// main_test.go installs a dev-auth hook that fires whenever AuthMode=="dev",
	// synthesizing an all-permissions principal and bypassing bearer auth. Use
	// the production "session" mode so real token authentication + scope
	// enforcement run.
	srv.cfg.AuthMode = "session"
	h := srv.Handler()
	ctx := context.Background()

	tenant, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("apitok-%d", time.Now().UnixNano()), "API token tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenantID := tenant.ID
	// The admin manages tokens (security.keys) and can read+write tests, so a
	// read-only token minted for it can be checked against both route kinds.
	_, adminTok := directoryPrincipal(t, db, tenantID, fmt.Sprintf("apitok-admin-%d@example.com", time.Now().UnixNano()),
		permSecurityKeys, permTestRead, permTestWrite)

	do := func(method, path, bearer string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	auditCount := func(action string) int {
		t.Helper()
		var n int
		if err := db.Pool().QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2`, tenantID, action).Scan(&n); err != nil {
			t.Fatalf("count audit %s: %v", action, err)
		}
		return n
	}

	// CREATE a read-only token via the API; the secret comes back exactly once.
	rec := do(http.MethodPost, "/v1/api-tokens", adminTok, map[string]any{"name": "ro", "scopes": []string{"read"}, "expires_in_hours": 24})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/api-tokens = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Token == "" || created.ID == "" {
		t.Fatalf("create response missing id/token: %v body=%s", err, rec.Body.String())
	}
	if auditCount("apitoken.create") < 1 {
		t.Error("create must write an apitoken.create audit event")
	}

	// A read-only token: 200 on a read route, 403 on a write route.
	if rec := do(http.MethodGet, "/v1/tests", created.Token, nil); rec.Code != http.StatusOK {
		t.Errorf("read-only token on GET /v1/tests = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPost, "/v1/tests", created.Token, map[string]any{"name": "x"}); rec.Code != http.StatusForbidden {
		t.Errorf("read-only token on POST /v1/tests = %d, want 403 (scope strips test.write)", rec.Code)
	}
	if auditCount("apitoken.first_use") < 1 {
		t.Error("the first use of a token must write an apitoken.first_use audit event")
	}

	// A SECOND token so per-token revoke can be shown to spare the others.
	rec = do(http.MethodPost, "/v1/api-tokens", adminTok, map[string]any{"name": "keep", "expires_in_hours": 24})
	if rec.Code != http.StatusCreated {
		t.Fatalf("second create = %d; body=%s", rec.Code, rec.Body.String())
	}
	var keep struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &keep)

	// LIST shows the tokens, never a secret.
	rec = do(http.MethodGet, "/v1/api-tokens", adminTok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/api-tokens = %d", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(created.Token)) || bytes.Contains(rec.Body.Bytes(), []byte(keep.Token)) {
		t.Error("the list response must never contain a token secret")
	}

	// REVOKE the read-only token; the other token keeps working.
	if rec := do(http.MethodDelete, "/v1/api-tokens/"+created.ID, adminTok, nil); rec.Code != http.StatusOK {
		t.Fatalf("DELETE /v1/api-tokens/%s = %d; body=%s", created.ID, rec.Code, rec.Body.String())
	}
	if auditCount("apitoken.revoke") < 1 {
		t.Error("revoke must write an apitoken.revoke audit event")
	}
	if rec := do(http.MethodGet, "/v1/tests", created.Token, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token = %d, want 401", rec.Code)
	}
	if rec := do(http.MethodGet, "/v1/tests", keep.Token, nil); rec.Code != http.StatusOK {
		t.Errorf("the user's OTHER token must still work after a per-token revoke: %d", rec.Code)
	}

	// EXPIRY: a token past expires_at is a 401 (minted directly with a past expiry).
	expiredSecret := "expired-http-" + tenantID
	adminUserID := keepOwner(ctx, t, db, tenantID)
	if _, err := store.NewMCPTokens(db.Pool()).CreateWithLifetime(ctx, tenantID, adminUserID, "expired", crypto.Hash([]byte(expiredSecret)), time.Now().Add(-time.Minute), nil); err != nil {
		t.Fatalf("mint expired token: %v", err)
	}
	if rec := do(http.MethodGet, "/v1/tests", expiredSecret, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("an expired token = %d, want 401", rec.Code)
	}
}

// keepOwner returns a user id in the tenant (any active user) to own the
// directly-minted expired token's FK.
func keepOwner(ctx context.Context, t *testing.T, db *store.DB, tenantID string) string {
	t.Helper()
	var id string
	if err := db.Pool().QueryRow(ctx,
		`SELECT id::text FROM users WHERE tenant_id = $1 ORDER BY created_at LIMIT 1`, tenantID).Scan(&id); err != nil {
		t.Fatalf("find a tenant user: %v", err)
	}
	return id
}
