// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// INV-03/RT-02: API/MCP bearer tokens must expire, must be revocable one at a
// time, and must carry a scope subset. Exercised against the real database so
// the expiry predicate and the per-token revoke run through actual SQL.
func TestMCPTokenExpiryScopesAndPerTokenRevoke(t *testing.T) {
	ctx := context.Background()
	admin := setup(ctx, t)
	defer admin.Close()
	tenantID, userID := sessionCleanupIdentity(ctx, t, admin, "token-lifecycle")
	m := NewMCPTokens(admin)

	// 1. Expiry: a token whose expires_at is in the past authenticates to nothing.
	expiredHash := crypto.Hash([]byte("expired-" + tenantID))
	if _, err := m.CreateWithLifetime(ctx, tenantID, userID, "expired", expiredHash, time.Now().Add(-time.Minute), nil); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	if _, err := m.AuthenticateFull(ctx, expiredHash); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("an expired token must be rejected with ErrInvalidToken, got %v", err)
	}

	// 2. A live, read-scoped token authenticates and reports its scope + first use.
	liveHash := crypto.Hash([]byte("live-" + tenantID))
	liveID, err := m.CreateWithLifetime(ctx, tenantID, userID, "live", liveHash, time.Now().Add(time.Hour), []string{"read"})
	if err != nil {
		t.Fatalf("create live token: %v", err)
	}
	res, err := m.AuthenticateFull(ctx, liveHash)
	if err != nil || res.TenantID != tenantID || res.UserID != userID {
		t.Fatalf("live token must authenticate: %+v err=%v", res, err)
	}
	if res.TokenID != liveID {
		t.Errorf("token id = %q, want %q", res.TokenID, liveID)
	}
	if len(res.Scopes) != 1 || res.Scopes[0] != "read" {
		t.Errorf("scopes = %v, want [read]", res.Scopes)
	}
	if !res.FirstUse {
		t.Error("the first authentication must report FirstUse=true")
	}
	res2, err := m.AuthenticateFull(ctx, liveHash)
	if err != nil {
		t.Fatal(err)
	}
	if res2.FirstUse {
		t.Error("a subsequent authentication must report FirstUse=false")
	}

	// 3. Per-token revoke leaves the user's OTHER tokens working (not all of them).
	aHash := crypto.Hash([]byte("a-" + tenantID))
	bHash := crypto.Hash([]byte("b-" + tenantID))
	aID, err := m.CreateWithLifetime(ctx, tenantID, userID, "token-a", aHash, time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateWithLifetime(ctx, tenantID, userID, "token-b", bHash, time.Now().Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	found, err := m.RevokeByID(ctx, tenantID, aID)
	if err != nil || !found {
		t.Fatalf("revoking token-a: found=%v err=%v", found, err)
	}
	if _, err := m.AuthenticateFull(ctx, aHash); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the revoked token must be rejected, got %v", err)
	}
	if _, err := m.AuthenticateFull(ctx, bHash); err != nil {
		t.Errorf("the user's OTHER token must still authenticate: %v", err)
	}
	if found, err := m.RevokeByID(ctx, tenantID, aID); err != nil || found {
		t.Errorf("re-revoking an already-revoked token must report not-found: found=%v err=%v", found, err)
	}

	// 4. List returns metadata (never the hash or the secret) for the tenant.
	list, err := m.List(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	sawLive := false
	for _, ti := range list {
		if ti.ID == liveID {
			sawLive = true
			if ti.ExpiresAt == nil {
				t.Error("the live token must report expires_at")
			}
			if len(ti.Scopes) != 1 || ti.Scopes[0] != "read" {
				t.Errorf("the live token's listed scopes = %v, want [read]", ti.Scopes)
			}
		}
	}
	if !sawLive {
		t.Error("List must include the live token")
	}
	if len(list) < 4 {
		t.Errorf("List should include every created token for the tenant, got %d", len(list))
	}
}
