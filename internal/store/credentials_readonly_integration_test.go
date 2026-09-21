// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestCredentialsAuthenticateOnAReadOnlyDatabase (DPR-096): every credential
// lookup used to verify AND stamp last-used in one UPDATE … RETURNING, so on
// a read-only standby (or a fenced writer pool) API tokens, sessions, OTLP
// tokens and SCIM tokens all failed with 401 — the documented "reads keep
// serving" failover promise held for nothing that authenticates. The stamp is
// now best-effort: authentication succeeds read-only, and the stamp lands
// again once writes are usable.
func TestCredentialsAuthenticateOnAReadOnlyDatabase(t *testing.T) {
	ctx := context.Background()
	admin := setup(ctx, t) // migrated; fixtures + assertions
	defer admin.Close()
	db, err := Open(ctx, dsn(), 4, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	pool := db.Pool() // the pool under the fence

	tenantID, userID := sessionCleanupIdentity(ctx, t, admin, "readonly-auth")
	mcpHash := crypto.Hash([]byte("ro-mcp-" + tenantID))
	otlpHash := crypto.Hash([]byte("ro-otlp-" + tenantID))
	scimHash := crypto.Hash([]byte("ro-scim-" + tenantID))
	sessHash := crypto.Hash([]byte("ro-session-" + tenantID))
	if _, err := NewMCPTokens(admin).Create(ctx, tenantID, userID, "ro", mcpHash); err != nil {
		t.Fatalf("create mcp token: %v", err)
	}
	if _, err := NewOTLPTokens(admin).Create(ctx, tenantID, "ro", otlpHash); err != nil {
		t.Fatalf("create otlp token: %v", err)
	}
	if _, err := NewScimTokens(admin).Create(ctx, tenantID, "ro", scimHash); err != nil {
		t.Fatalf("create scim token: %v", err)
	}
	if err := NewSessions(admin).Create(ctx, sessHash, auth.Session{
		TenantID: tenantID, UserID: userID, Email: "ro@example.com", DisplayName: "RO",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	authenticateAll := func(phase string) {
		t.Helper()
		if tid, uid, err := NewMCPTokens(pool).Authenticate(ctx, mcpHash); err != nil || tid != tenantID || uid != userID {
			t.Fatalf("%s: mcp token must authenticate: tid=%q uid=%q err=%v", phase, tid, uid, err)
		}
		if tid, err := NewOTLPTokens(pool).Authenticate(ctx, otlpHash); err != nil || tid != tenantID {
			t.Fatalf("%s: otlp token must authenticate: tid=%q err=%v", phase, tid, err)
		}
		if tid, err := NewScimTokens(pool).Authenticate(ctx, scimHash); err != nil || tid != tenantID {
			t.Fatalf("%s: scim token must authenticate: tid=%q err=%v", phase, tid, err)
		}
		sess, err := NewSessions(pool).LookupByHash(ctx, sessHash, time.Hour)
		if err != nil || sess == nil || sess.UserID != userID {
			t.Fatalf("%s: session must resolve: sess=%+v err=%v", phase, sess, err)
		}
	}
	stamped := func(table string, hash []byte) bool {
		t.Helper()
		var n int
		inTenant(ctx, t, admin, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			col := "last_used_at"
			if table == "sessions" {
				col = "last_activity_at"
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE token_hash = $1 AND `+col+` > now() - interval '30 seconds'`, hash).Scan(&n)
		})
		return n == 1
	}

	// Read-only: the writer pool is fenced exactly as it is on a stale
	// ex-primary, which also mirrors a hot standby's refusal to write.
	if !db.FenceWrites(true) {
		t.Fatal("fence must engage")
	}
	authenticateAll("read-only")
	for _, c := range []struct {
		table string
		hash  []byte
	}{{"mcp_tokens", mcpHash}, {"otlp_tokens", otlpHash}, {"scim_tokens", scimHash}} {
		if stamped(c.table, c.hash) {
			t.Fatalf("read-only: %s must not have been stamped", c.table)
		}
	}

	// Writable again: authentication still works and the stamps land.
	db.FenceWrites(false)
	authenticateAll("writable")
	for _, c := range []struct {
		table string
		hash  []byte
	}{{"mcp_tokens", mcpHash}, {"otlp_tokens", otlpHash}, {"scim_tokens", scimHash}, {"sessions", sessHash}} {
		if !stamped(c.table, c.hash) {
			t.Fatalf("writable: %s must be stamped on authentication", c.table)
		}
	}

	// A revoked token stays refused whether or not the stamp can land.
	if err := NewMCPTokens(admin).RevokeForUser(ctx, tenantID, userID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	db.FenceWrites(true)
	if _, _, err := NewMCPTokens(pool).Authenticate(ctx, mcpHash); err == nil {
		t.Fatal("a revoked token must be refused on a read-only database too")
	}
}
