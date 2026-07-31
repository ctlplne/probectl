// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

// U-057: integration coverage for the store paths the first pass still skipped —
// the DB/pool lifecycle, the full user lifecycle, RBAC roles/bindings/permissions,
// sessions, agent enrollment (tokens/identities/CA), ABAC policies, alert ops,
// provider operator get/list + break-glass, the org/team/project getters, tenant
// listing, and agent heartbeat-batch. All run against the real schema (RLS
// included) through the same setup/skip harness, raising the 60% floor honestly.

// covUUID mints a unique v4 UUID for fixtures keyed on uuid/serial columns.
func covUUID(t *testing.T) string {
	t.Helper()
	b, err := crypto.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// store.Open + pool lifecycle (Open/openPool/Ping/Pool/ReadPool/WithReadReplica/Close).
func TestStoreOpenPingPool(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, dsn(), 5, 1, 5*time.Second)
	if err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if db.Pool() == nil {
		t.Fatal("Pool() is nil")
	}
	// No replica yet → ReadPool falls back to the primary.
	if db.ReadPool() == nil {
		t.Fatal("ReadPool() is nil before a replica is configured")
	}
	// Attach a read replica (same DSN — exercises the wiring).
	if err := db.WithReadReplica(ctx, dsn(), 2, 0, 5*time.Second); err != nil {
		t.Fatalf("WithReadReplica: %v", err)
	}
	if db.ReadPool() == nil {
		t.Fatal("ReadPool() is nil after a replica is configured")
	}
}

// Users: Create, CreateSCIM (+ strOrNil/orEmptyAttrs/statusOrActive), Get,
// GetByExternalID, Update, UpdateStatus, List (all + filtered), Delete.
func TestUserLifecycleStore(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("usr-%d", time.Now().UnixNano()), "Users")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		u, err := (Users{}).Create(ctx, s, "u-"+sfx+"@x.com", "Plain User")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if got, err := (Users{}).Get(ctx, s, u.ID); err != nil || got.Email != u.Email {
			t.Fatalf("get: %v / %+v", err, got)
		}
		scim, err := (Users{}).CreateSCIM(ctx, s, User{
			Email: "s-" + sfx + "@x.com", DisplayName: "SCIM User",
			UserName: "s-" + sfx, ExternalID: "ext-" + sfx,
			Attributes: map[string]string{"department": "netops"},
		})
		if err != nil {
			t.Fatalf("createSCIM: %v", err)
		}
		if got, err := (Users{}).GetByExternalID(ctx, s, "ext-"+sfx); err != nil || got.ID != scim.ID {
			t.Fatalf("getByExternalID: %v / %+v", err, got)
		}
		if _, err := (Users{}).Update(ctx, s, scim.ID, User{
			Email: "s2-" + sfx + "@x.com", DisplayName: "SCIM Two",
			UserName: "s2-" + sfx, ExternalID: "ext-" + sfx,
			Attributes: map[string]string{"department": "sre"}, Status: "active",
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		if got, err := (Users{}).UpdateStatus(ctx, s, scim.ID, "suspended"); err != nil || got.Status != "suspended" {
			t.Fatalf("updateStatus: %v / %+v", err, got)
		}
		if all, err := (Users{}).List(ctx, s, ""); err != nil || len(all) < 2 {
			t.Fatalf("list all: %v / %d", err, len(all))
		}
		if filtered, err := (Users{}).List(ctx, s, "s2-"+sfx); err != nil || len(filtered) != 1 {
			t.Fatalf("list filtered: %v / %d", err, len(filtered))
		}
		if err := (Users{}).Delete(ctx, s, u.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		return nil
	})
}

// RBAC: Roles get/getBySlug/list/addPermission/permissions/delete; RoleBindings
// bind/create/count/members/unbind; Permissions.ForSubject.
func TestRBACStore(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("rbac-%d", time.Now().UnixNano()), "RBAC")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		role, err := (Roles{}).Create(ctx, s, "role-"+sfx, "Role "+sfx, "desc")
		if err != nil {
			t.Fatalf("role create: %v", err)
		}
		if _, err := (Roles{}).Get(ctx, s, role.ID); err != nil {
			t.Fatalf("role get: %v", err)
		}
		if _, err := (Roles{}).GetBySlug(ctx, s, role.Slug); err != nil {
			t.Fatalf("role getBySlug: %v", err)
		}
		if roles, err := (Roles{}).List(ctx, s); err != nil || len(roles) == 0 {
			t.Fatalf("role list: %v / %d", err, len(roles))
		}
		if err := (Roles{}).AddPermission(ctx, s, role.ID, "test.read"); err != nil {
			t.Fatalf("addPermission: %v", err)
		}
		if perms, err := (Roles{}).Permissions(ctx, s, role.ID); err != nil || len(perms) != 1 {
			t.Fatalf("permissions: %v / %v", err, perms)
		}
		u1, err := (Users{}).Create(ctx, s, "rb1-"+sfx+"@x.com", "Bind One")
		if err != nil {
			t.Fatalf("user1: %v", err)
		}
		u2, err := (Users{}).Create(ctx, s, "rb2-"+sfx+"@x.com", "Bind Two")
		if err != nil {
			t.Fatalf("user2: %v", err)
		}
		if err := (RoleBindings{}).Bind(ctx, s, "user", u1.ID, role.ID); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if _, err := (RoleBindings{}).Create(ctx, s, "user", u2.ID, role.ID, "tenant", nil); err != nil {
			t.Fatalf("rolebinding create: %v", err)
		}
		if n, err := (RoleBindings{}).CountForSubject(ctx, s, "user", u1.ID); err != nil || n != 1 {
			t.Fatalf("countForSubject: %v / %d", err, n)
		}
		if members, err := (RoleBindings{}).MembersOfRole(ctx, s, role.ID); err != nil || len(members) != 2 {
			t.Fatalf("membersOfRole: %v / %v", err, members)
		}
		if perms, err := (Permissions{}).ForSubject(ctx, s, "user", u1.ID); err != nil || len(perms) == 0 {
			t.Fatalf("forSubject: %v / %v", err, perms)
		}
		if err := (RoleBindings{}).Unbind(ctx, s, "user", u1.ID, role.ID); err != nil {
			t.Fatalf("unbind: %v", err)
		}
		r2, err := (Roles{}).Create(ctx, s, "role2-"+sfx, "Role Two", "")
		if err != nil {
			t.Fatalf("role2 create: %v", err)
		}
		if err := (Roles{}).Delete(ctx, s, r2.ID); err != nil {
			t.Fatalf("role delete: %v", err)
		}
		return nil
	})
}

// Sessions (pool-based, global lookup): Create, idle-touching LookupByHash,
// atomic RotateByHash, DeleteByHash, DeleteAllForUser. Needs a real tenant +
// user (FKs).
func TestSessionStoreCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("sess-%d", time.Now().UnixNano()), "Sessions")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	var userID string
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		u, err := (Users{}).Create(ctx, s, "sess-"+sfx+"@x.com", "Sess User")
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		userID = u.ID
		return nil
	})
	sess := NewSessions(pool)
	h1 := crypto.Hash([]byte("sess1-" + sfx))
	if err := sess.Create(ctx, h1, auth.Session{
		TenantID: tn.ID, UserID: userID, Email: "sess-" + sfx + "@x.com",
		DisplayName: "Sess User", MFASatisfied: true, TimeZone: "Asia/Tokyo", Locale: "ar-EG",
		TenantTimeZone: "America/New_York", TenantLocale: "es", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("session create: %v", err)
	}
	if got, err := sess.LookupByHash(ctx, h1, time.Minute); err != nil || got == nil || got.UserID != userID ||
		got.TimeZone != "Asia/Tokyo" || got.Locale != "ar-EG" ||
		got.TenantTimeZone != "America/New_York" || got.TenantLocale != "es" {
		t.Fatalf("lookupByHash: %v / %+v", err, got)
	}
	other, err := NewTenants(pool).Create(ctx, fmt.Sprintf("sess-other-%d", time.Now().UnixNano()), "Other Sessions")
	if err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	badHash := crypto.Hash([]byte("cross-tenant-session-" + sfx))
	if err := sess.Create(ctx, badHash, auth.Session{
		TenantID: other.ID, UserID: userID, Email: "mismatch@x.com", ExpiresAt: time.Now().Add(time.Hour),
	}); err == nil {
		t.Fatal("cross-tenant tenant/user session pair was accepted by storage")
	}
	if ok, err := sess.RotateByHash(ctx, h1, badHash, auth.Session{
		TenantID: other.ID, UserID: userID, Email: "mismatch@x.com", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil || ok {
		t.Fatalf("cross-tenant rotation must return not-rotated without changing the source: err=%v rotated=%t", err, ok)
	}
	if got, err := sess.LookupByHash(ctx, h1, time.Minute); err != nil || got == nil || got.TenantID != tn.ID {
		t.Fatalf("failed cross-tenant rotation did not preserve original: %v / %+v", err, got)
	}
	hRotated := crypto.Hash([]byte("sess1-rotated-" + sfx))
	if ok, err := sess.RotateByHash(ctx, h1, hRotated, auth.Session{
		TenantID: tn.ID, UserID: userID, Email: "sess-" + sfx + "@x.com",
		ExpiresAt: time.Now().Add(time.Hour), AuthorizationHash: crypto.Hash([]byte("viewer")),
	}); err != nil || !ok {
		t.Fatalf("rotateByHash: %v / %t", err, ok)
	}
	if got, err := sess.LookupByHash(ctx, h1, time.Minute); err != nil || got != nil {
		t.Fatalf("old hash survived rotation: %v / %+v", err, got)
	}
	if got, err := sess.LookupByHash(ctx, hRotated, time.Minute); err != nil || got == nil || got.TenantID != tn.ID {
		t.Fatalf("rotated lookup: %v / %+v", err, got)
	}
	if err := sess.DeleteByHash(ctx, hRotated); err != nil {
		t.Fatalf("deleteByHash: %v", err)
	}
	hIdle := crypto.Hash([]byte("sess-idle-" + sfx))
	if err := sess.Create(ctx, hIdle, auth.Session{
		TenantID: tn.ID, UserID: userID, Email: "sess-" + sfx + "@x.com",
		ExpiresAt: time.Now().Add(time.Hour), LastActivityAt: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("idle session create: %v", err)
	}
	if got, err := sess.LookupByHash(ctx, hIdle, 30*time.Minute); err != nil || got != nil {
		t.Fatalf("idle session must fail closed: %v / %+v", err, got)
	}
	if err := sess.DeleteByHash(ctx, hIdle); err != nil {
		t.Fatalf("idle session cleanup: %v", err)
	}
	h2 := crypto.Hash([]byte("sess2-" + sfx))
	if err := sess.Create(ctx, h2, auth.Session{
		TenantID: tn.ID, UserID: userID, Email: "sess-" + sfx + "@x.com",
		DisplayName: "Sess User", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("session create 2: %v", err)
	}
	if n, err := sess.DeleteAllForUser(ctx, tn.ID, userID); err != nil || n < 1 {
		t.Fatalf("deleteAllForUser: %v / %d", err, n)
	}
}

// TestAuthenticatedLoginSessionReplacement exercises the login-only session
// path against real PostgreSQL. It proves three properties together:
//
//   - a predecessor from tenant A is invalidated at the storage boundary while
//     the fresh, independently authenticated tenant-B identity is adopted;
//   - stale identity/MFA/lifetime fields never survive the new login;
//   - two concurrent replacements of one predecessor create exactly one live
//     successor.
func TestAuthenticatedLoginSessionReplacement(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	oldTenant, err := NewTenants(pool).Create(ctx, "login-old-"+suffix, "Old Login Tenant")
	if err != nil {
		t.Fatalf("old tenant: %v", err)
	}
	newTenant, err := NewTenants(pool).Create(ctx, "login-new-"+suffix, "New Login Tenant")
	if err != nil {
		t.Fatalf("new tenant: %v", err)
	}
	var oldUserID, newUserID string
	inTenant(ctx, t, pool, oldTenant.ID, func(ctx context.Context, scope tenancy.Scope) error {
		user, err := (Users{}).Create(ctx, scope, "old-login-"+suffix+"@example.com", "Old Login")
		if err == nil {
			oldUserID = user.ID
		}
		return err
	})
	inTenant(ctx, t, pool, newTenant.ID, func(ctx context.Context, scope tenancy.Scope) error {
		user, err := (Users{}).Create(ctx, scope, "new-login-"+suffix+"@example.com", "Fresh Login")
		if err == nil {
			newUserID = user.ID
		}
		return err
	})

	sessions := NewSessions(pool)
	oldHash := crypto.Hash([]byte("authenticated-old-" + suffix))
	if err := sessions.Create(ctx, oldHash, auth.Session{
		TenantID:       oldTenant.ID,
		UserID:         oldUserID,
		Email:          "old-login-" + suffix + "@example.com",
		DisplayName:    "Old Login",
		MFASatisfied:   true,
		TimeZone:       "Asia/Kolkata",
		Locale:         "en-IN",
		TenantTimeZone: "UTC",
		TenantLocale:   "en",
		CreatedAt:      time.Now().Add(-4 * time.Hour),
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("create predecessor: %v", err)
	}

	freshCreated := time.Now()
	freshExpires := freshCreated.Add(2 * time.Hour)
	freshHash := crypto.Hash([]byte("authenticated-fresh-" + suffix))
	freshAuthorization := crypto.Hash([]byte("fresh-permissions-" + suffix))
	created, err := sessions.ReplaceAuthenticatedByHash(ctx, oldHash, nil, freshHash, auth.Session{
		TenantID:          newTenant.ID,
		UserID:            newUserID,
		Email:             "new-login-" + suffix + "@example.com",
		DisplayName:       "Fresh Login",
		MFASatisfied:      false,
		TimeZone:          "America/New_York",
		Locale:            "es",
		TenantTimeZone:    "Europe/Paris",
		TenantLocale:      "fr",
		CreatedAt:         freshCreated,
		LastActivityAt:    freshCreated,
		ExpiresAt:         freshExpires,
		AuthorizationHash: freshAuthorization,
	})
	if err != nil || !created {
		t.Fatalf("replace authenticated session: created=%t err=%v", created, err)
	}
	if got, err := sessions.LookupByHash(ctx, oldHash, time.Hour); err != nil || got != nil {
		t.Fatalf("tenant-A predecessor survived replacement: session=%+v err=%v", got, err)
	}
	got, err := sessions.LookupByHash(ctx, freshHash, time.Hour)
	if err != nil || got == nil {
		t.Fatalf("fresh tenant-B session did not resolve: session=%+v err=%v", got, err)
	}
	if got.TenantID != newTenant.ID || got.UserID != newUserID ||
		got.Email != "new-login-"+suffix+"@example.com" || got.DisplayName != "Fresh Login" ||
		got.MFASatisfied ||
		got.TimeZone != "America/New_York" || got.Locale != "es" ||
		got.TenantTimeZone != "Europe/Paris" || got.TenantLocale != "fr" {
		t.Fatalf("fresh authenticated authority was not adopted: %+v", got)
	}
	if got.CreatedAt.Sub(freshCreated).Abs() > time.Millisecond ||
		got.ExpiresAt.Sub(freshExpires).Abs() > time.Millisecond {
		t.Fatalf("fresh lifetime changed: created=%v want=%v expires=%v want=%v",
			got.CreatedAt, freshCreated, got.ExpiresAt, freshExpires)
	}

	// The global hash-only locator is the inactive concurrency tombstone. The
	// old session's detailed identity stays private in tenant A; moving or
	// editing it from tenant B's replacement transaction would cross the
	// physical-silo boundary.
	var replaced bool
	if err := pool.QueryRow(ctx,
		`SELECT replaced_at IS NOT NULL
		   FROM credential_locators
		  WHERE credential_kind = 'session' AND token_hash = $1`,
		oldHash,
	).Scan(&replaced); err != nil {
		t.Fatalf("read predecessor locator tombstone: %v", err)
	}
	if !replaced {
		t.Fatal("predecessor locator was not retained as an inactive tombstone")
	}
	inTenant(ctx, t, pool, newTenant.ID, func(ctx context.Context, scope tenancy.Scope) error {
		var count int
		if err := scope.Q.QueryRow(ctx,
			`SELECT count(*) FROM sessions WHERE token_hash = $1`,
			oldHash,
		).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("tenant B observed tenant A's predecessor tombstone: count=%d", count)
		}
		return nil
	})
	// A stale tab may send logout after the winning callback. That must not
	// erase the consumed-token marker and reopen a second-successor race.
	if err := sessions.DeleteByHash(ctx, oldHash); err != nil {
		t.Fatalf("logout obsolete predecessor: %v", err)
	}
	obsoleteRetryHash := crypto.Hash([]byte("authenticated-obsolete-retry-" + suffix))
	if created, err := sessions.ReplaceAuthenticatedByHash(
		ctx, oldHash, nil, obsoleteRetryHash,
		auth.Session{
			TenantID: newTenant.ID, UserID: newUserID,
			ExpiresAt: time.Now().Add(time.Hour),
		},
	); err != nil || created {
		t.Fatalf("obsolete-token retry after logout: created=%t err=%v, want false/nil", created, err)
	}

	concurrentOldHash := crypto.Hash([]byte("authenticated-concurrent-old-" + suffix))
	if err := sessions.Create(ctx, concurrentOldHash, auth.Session{
		TenantID: oldTenant.ID, UserID: oldUserID,
		Email:        "old-login-" + suffix + "@example.com",
		MFASatisfied: true, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create concurrent predecessor: %v", err)
	}
	concurrentHashes := [][]byte{
		crypto.Hash([]byte("authenticated-concurrent-a-" + suffix)),
		crypto.Hash([]byte("authenticated-concurrent-b-" + suffix)),
	}
	type replacementResult struct {
		created bool
		err     error
	}
	results := make(chan replacementResult, len(concurrentHashes))
	start := make(chan struct{})
	var callers sync.WaitGroup
	for _, nextHash := range concurrentHashes {
		nextHash := nextHash
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			created, err := sessions.ReplaceAuthenticatedByHash(
				ctx, concurrentOldHash, nil, nextHash,
				auth.Session{
					TenantID: newTenant.ID, UserID: newUserID,
					Email:        "new-login-" + suffix + "@example.com",
					MFASatisfied: false, ExpiresAt: time.Now().Add(time.Hour),
				},
			)
			results <- replacementResult{created: created, err: err}
		}()
	}
	close(start)
	callers.Wait()
	close(results)

	var winners, losers int
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent replacement: %v", result.err)
		}
		if result.created {
			winners++
		} else {
			losers++
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("concurrent replacement outcomes: winners=%d losers=%d, want 1/1", winners, losers)
	}
	var liveSuccessors int
	for _, nextHash := range concurrentHashes {
		got, err := sessions.LookupByHash(ctx, nextHash, time.Hour)
		if err != nil {
			t.Fatalf("lookup concurrent successor: %v", err)
		}
		if got != nil {
			liveSuccessors++
		}
	}
	if liveSuccessors != 1 {
		t.Fatalf("live concurrent successors = %d, want exactly 1", liveSuccessors)
	}
	retryHash := crypto.Hash([]byte("authenticated-concurrent-retry-" + suffix))
	if created, err := sessions.ReplaceAuthenticatedByHash(
		ctx, concurrentOldHash, nil, retryHash,
		auth.Session{
			TenantID: newTenant.ID, UserID: newUserID,
			ExpiresAt: time.Now().Add(time.Hour),
		},
	); err != nil || created {
		t.Fatalf("consumed predecessor retry: created=%t err=%v, want false/nil", created, err)
	}
}

// Agent enrollment: EnrollTokens create/consume/revoke, AgentIdentities
// record/knownSerial/revokeAgent/isRevoked/listRevoked (+ the mapWriteErr
// conflict path via a duplicate serial), AgentCA save/load.
func TestEnrollmentStore(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("enr-%d", time.Now().UnixNano()), "Enroll")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())

	et := NewEnrollTokens(pool)
	consumeHash := crypto.Hash([]byte("join-" + sfx))
	if _, err := et.Create(ctx, tn.ID, "", "join-a", "operator", consumeHash, time.Hour); err != nil {
		t.Fatalf("enroll token create: %v", err)
	}
	gotTenant, pinned, err := et.Consume(ctx, consumeHash, "agent-x")
	if err != nil || gotTenant != tn.ID || pinned != "" {
		t.Fatalf("consume: %v / %s / %q", err, gotTenant, pinned)
	}
	// A re-consume of a burnt token is indistinguishable from any bad token.
	if _, _, err := et.Consume(ctx, consumeHash, "agent-x"); err == nil {
		t.Fatal("re-consume of a used token should fail")
	}
	revHash := crypto.Hash([]byte("join-rev-" + sfx))
	revID, err := et.Create(ctx, tn.ID, "", "join-b", "operator", revHash, time.Hour)
	if err != nil {
		t.Fatalf("enroll token create 2: %v", err)
	}
	if _, err := et.Revoke(ctx, revID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	ai := NewAgentIdentities(pool)
	agentID := covUUID(t)
	serial := "serial-" + sfx
	spiffe := "spiffe://probectl/tenant/" + tn.ID + "/agent/" + agentID
	if err := ai.Record(ctx, tn.ID, agentID, spiffe, serial, time.Now().Add(24*time.Hour), ""); err != nil {
		t.Fatalf("record identity: %v", err)
	}
	// Duplicate serial → UNIQUE violation mapped via mapWriteErr.
	if err := ai.Record(ctx, tn.ID, agentID, spiffe, serial, time.Now().Add(24*time.Hour), ""); err == nil {
		t.Fatal("duplicate serial should conflict")
	}
	if ok, err := ai.KnownSerial(ctx, tn.ID, agentID, serial); err != nil || !ok {
		t.Fatalf("knownSerial: %v / %v", err, ok)
	}
	if ok, err := ai.IsAgentRevoked(ctx, tn.ID, agentID); err != nil || ok {
		t.Fatalf("isAgentRevoked(before): %v / %v", err, ok)
	}
	serials, sp, err := ai.RevokeAgent(ctx, tn.ID, agentID, "operator")
	if err != nil || sp != spiffe || len(serials) != 1 {
		t.Fatalf("revokeAgent: %v / %s / %v", err, sp, serials)
	}
	if ok, err := ai.IsAgentRevoked(ctx, tn.ID, agentID); err != nil || !ok {
		t.Fatalf("isAgentRevoked(after): %v / %v", err, ok)
	}
	// TENANT-009: the known-tenant reads run under InTenant, so a DIFFERENT
	// tenant's scope can never see this tenant's serial — RLS confines the
	// lookup even though both share the bare pool.
	other, err := NewTenants(pool).Create(ctx, fmt.Sprintf("enr-other-%d", time.Now().UnixNano()), "Other")
	if err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	if ok, err := ai.KnownSerial(ctx, other.ID, agentID, serial); err != nil || ok {
		t.Fatalf("cross-tenant KnownSerial saw another tenant's serial: %v / %v (RLS leak)", err, ok)
	}
	if rs, sps, err := ai.ListRevoked(ctx); err != nil || len(rs) == 0 || len(sps) == 0 {
		t.Fatalf("listRevoked: %v / %v / %v", err, rs, sps)
	}
	if rs, sps, err := NewBMPRevocations(pool).List(ctx); err != nil ||
		!containsString(rs, serial) || !containsString(sps, spiffe) {
		t.Fatalf("BMP execute-only revocation snapshot: %v / %v / %v", err, rs, sps)
	}
	roleTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = roleTx.Rollback(ctx) }()
	if _, err := roleTx.Exec(ctx, "SET LOCAL ROLE "+BMPRevocationReaderRole); err != nil {
		t.Fatalf("assume BMP revocation reader: %v", err)
	}
	var canReadIdentities, canExecuteSnapshot bool
	if err := roleTx.QueryRow(ctx,
		`SELECT
		    has_table_privilege(current_user, 'public.agent_identities', 'SELECT'),
		    has_function_privilege(
		        current_user,
		        'public.provider_list_revoked_agent_identities()',
		        'EXECUTE'
		    )`,
	).Scan(&canReadIdentities, &canExecuteSnapshot); err != nil {
		t.Fatalf("inspect BMP revocation reader grants: %v", err)
	}
	if canReadIdentities || !canExecuteSnapshot {
		t.Fatalf(
			"BMP revocation role grants: table_select=%v snapshot_execute=%v",
			canReadIdentities,
			canExecuteSnapshot,
		)
	}
	if err := roleTx.Rollback(ctx); err != nil {
		t.Fatalf("rollback BMP revocation role inspection: %v", err)
	}

	ca := NewAgentCA(pool)
	if err := ca.Save(ctx, "root", "ROOT-CERT-"+sfx, ""); err != nil {
		t.Fatalf("ca save root: %v", err)
	}
	if err := ca.Save(ctx, "intermediate", "INT-CERT-"+sfx, "SEALED-"+sfx); err != nil {
		t.Fatalf("ca save intermediate: %v", err)
	}
	// agent_ca is a shared (global) table other suites may upsert concurrently
	// under ./... — assert presence, not an exact value, to stay deterministic.
	if cert, _, err := ca.Load(ctx, "intermediate"); err != nil || cert == "" {
		t.Fatalf("ca load intermediate: %v / %q", err, cert)
	}
	if cert, _, err := ca.Load(ctx, "root"); err != nil || cert == "" {
		t.Fatalf("ca load root: %v / %q", err, cert)
	}
}

// ABAC policies: Create, List, Delete (tenant-scoped).
func TestABACPolicyStore(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("abac-%d", time.Now().UnixNano()), "ABAC")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		p, err := (ABACPolicies{}).Create(ctx, s, auth.Policy{
			Name: "pol-" + sfx, Effect: auth.PolicyDeny, Permission: "test.write",
			Subject: map[string]string{"department": "contractor"}, Priority: 10, Enabled: true,
		})
		if err != nil {
			t.Fatalf("abac create: %v", err)
		}
		if list, err := (ABACPolicies{}).List(ctx, s); err != nil || len(list) != 1 {
			t.Fatalf("abac list: %v / %d", err, len(list))
		}
		if err := (ABACPolicies{}).Delete(ctx, s, p.ID); err != nil {
			t.Fatalf("abac delete: %v", err)
		}
		return nil
	})
}

// Alert ops (silences/acks): Upsert (insert + ON CONFLICT update), List, Delete.
func TestAlertOpsStore(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("aops-%d", time.Now().UnixNano()), "AlertOps")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Second)
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		fp := "fp-" + sfx
		if err := (AlertOps{}).Upsert(ctx, s, AlertOp{Fingerprint: fp, RuleID: "rule-" + sfx, AckedBy: "dev@x", AckedAt: &now}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		until := now.Add(time.Hour)
		if err := (AlertOps{}).Upsert(ctx, s, AlertOp{Fingerprint: fp, RuleID: "rule-" + sfx, SilencedUntil: &until}); err != nil {
			t.Fatalf("re-upsert: %v", err)
		}
		if ops, err := (AlertOps{}).List(ctx, s); err != nil || len(ops) != 1 {
			t.Fatalf("list: %v / %d", err, len(ops))
		}
		if err := (AlertOps{}).Delete(ctx, s, fp); err != nil {
			t.Fatalf("delete: %v", err)
		}
		return nil
	})
}

// Provider operators get/list + break-glass grant/listActive/revoke.
func TestProviderGetListAndBreakGlass(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	ops := NewOperators(pool)
	op, err := ops.Create(ctx, "op-"+sfx+"@x.com", "Operator "+sfx)
	if err != nil {
		t.Fatalf("operator create: %v", err)
	}
	if got, err := ops.Get(ctx, op.ID); err != nil || got.Email != op.Email {
		t.Fatalf("operator get: %v / %+v", err, got)
	}
	if list, err := ops.List(ctx); err != nil || len(list) == 0 {
		t.Fatalf("operator list: %v / %d", err, len(list))
	}
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("bg-%d", time.Now().UnixNano()), "BreakGlass")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	bg := NewBreakGlass(pool)
	grant, err := bg.Grant(ctx, op.ID, tn.ID, "incident triage", "read", "admin@x", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if active, err := bg.ListActive(ctx, tn.ID); err != nil || len(active) != 1 {
		t.Fatalf("listActive: %v / %d", err, len(active))
	}
	if err := bg.Revoke(ctx, grant.ID, "admin@x"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if active, err := bg.ListActive(ctx, tn.ID); err != nil || len(active) != 0 {
		t.Fatalf("listActive after revoke: %v / %d", err, len(active))
	}
}

// Hierarchy getters: Organizations.Get/List, Teams.Get, Projects.Get.
func TestHierarchyGetters(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("hier-%d", time.Now().UnixNano()), "Hier")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		org, err := (Organizations{}).Create(ctx, s, "org-"+sfx, "Org")
		if err != nil {
			t.Fatalf("org create: %v", err)
		}
		if _, err := (Organizations{}).Get(ctx, s, org.ID); err != nil {
			t.Fatalf("org get: %v", err)
		}
		if orgs, err := (Organizations{}).List(ctx, s); err != nil || len(orgs) == 0 {
			t.Fatalf("org list: %v / %d", err, len(orgs))
		}
		team, err := (Teams{}).Create(ctx, s, org.ID, "team-"+sfx, "Team")
		if err != nil {
			t.Fatalf("team create: %v", err)
		}
		if _, err := (Teams{}).Get(ctx, s, team.ID); err != nil {
			t.Fatalf("team get: %v", err)
		}
		proj, err := (Projects{}).Create(ctx, s, team.ID, "proj-"+sfx, "Proj")
		if err != nil {
			t.Fatalf("project create: %v", err)
		}
		if _, err := (Projects{}).Get(ctx, s, proj.ID); err != nil {
			t.Fatalf("project get: %v", err)
		}
		return nil
	})
}

// Tenants.List (global).
func TestTenantsList(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	if _, err := NewTenants(pool).Create(ctx, fmt.Sprintf("tl-%d", time.Now().UnixNano()), "TList"); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if list, err := NewTenants(pool).List(ctx); err != nil || len(list) == 0 {
		t.Fatalf("tenant list: %v / %d", err, len(list))
	}
}

// Agents.HeartbeatBatch (bulk liveness update).
func TestAgentsHeartbeatBatch(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("hb-%d", time.Now().UnixNano()), "HB")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		var ids []string
		for i := 0; i < 2; i++ {
			id := covUUID(t)
			if _, err := (Agents{}).Register(ctx, s, id, fmt.Sprintf("a%d-%s", i, sfx), "host", "0.1.0",
				"spiffe://probectl/tenant/"+tn.ID+"/agent/"+id, []string{"icmp"}); err != nil {
				t.Fatalf("register: %v", err)
			}
			ids = append(ids, id)
		}
		if err := (Agents{}).HeartbeatBatch(ctx, s, ids); err != nil {
			t.Fatalf("heartbeatBatch: %v", err)
		}
		return nil
	})
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
