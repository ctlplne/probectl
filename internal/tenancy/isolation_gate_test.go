// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

// Cross-tenant isolation gate — the permanent CI gate (docs/guardrails.md G7-1).
// Seeded as a placeholder in S0; this is the real suite from S2.
//
// It proves isolation at BOTH layers required by PRD §3.2 ("a missing application
// check cannot leak data"): the repository (query) layer scopes reads, and a raw,
// predicate-free query still returns only the caller's rows because Row-Level
// Security is enforced by the database. It also proves fail-closed behavior and
// that the provider plane is a separate, cross-tenant domain.
package tenancy_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func dsn() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl@localhost:5432/postgres?sslmode=disable"
}

// setup connects, applies migrations (schema + RLS + the probectl_app role), and
// skips when no database is available.
func setup(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		// TEST-003: CI (PROBECTL_TEST_REQUIRE_SERVICES=1) fails the isolation
		// gate on a missing DB rather than skipping it.
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func TestCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tenants := store.NewTenants(pool)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	ta, err := tenants.Create(ctx, "iso-a-"+suffix, "Iso A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tb, err := tenants.Create(ctx, "iso-b-"+suffix, "Iso B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	orgs := store.Organizations{}
	var bOrg string
	mustScope(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		_, err := orgs.Create(ctx, s, "a-org", "A Org")
		return err
	})
	mustScope(ctx, t, pool, tb.ID, func(ctx context.Context, s tenancy.Scope) error {
		o, err := orgs.Create(ctx, s, "b-org", "B Org")
		if err == nil {
			bOrg = o.ID
		}
		return err
	})

	mustScope(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		// Query layer: the repository sees only tenant A's organization.
		list, err := orgs.List(ctx, s)
		if err != nil {
			return err
		}
		if len(list) != 1 || list[0].Slug != "a-org" || list[0].TenantID != ta.ID {
			t.Errorf("tenant A org list = %+v, want exactly its own org", list)
		}
		// Storage layer: a RAW, predicate-free query still returns only A's rows.
		var raw int
		if err := s.Q.QueryRow(ctx, "SELECT count(*) FROM organizations").Scan(&raw); err != nil {
			return err
		}
		if raw != 1 {
			t.Errorf("raw unscoped org count in tenant A = %d, want 1 (RLS LEAK)", raw)
		}
		// Tenant B's organization must be invisible to A.
		if _, err := orgs.Get(ctx, s, bOrg); err == nil {
			t.Error("tenant A could read tenant B's organization (CROSS-TENANT LEAK)")
		}
		return nil
	})

	// The provider plane (no tenant scope) sees all tenants.
	all, err := tenants.List(ctx)
	if err != nil {
		t.Fatalf("provider list: %v", err)
	}
	if !containsTenant(all, ta.ID) || !containsTenant(all, tb.ID) {
		t.Error("provider tenant list should include both tenants")
	}

	// Fail closed: a tenant-scoped operation with no tenant in context errors.
	err = tenancy.InTenant(ctx, pool, func(context.Context, tenancy.Scope) error { return nil })
	if !errors.Is(err, tenancy.ErrNoTenant) {
		t.Errorf("InTenant without a tenant = %v, want ErrNoTenant", err)
	}
}

// TestMCPTokenPolicyConfinesRawTenantReads pins the 0040/0059 RLS contract:
// pre-tenant token authentication still resolves its tenant, but once a tenant
// GUC is set even a predicate-free raw query cannot see another tenant's token.
func TestMCPTokenPolicyConfinesRawTenantReads(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenants := store.NewTenants(pool)
	ta, err := tenants.Create(ctx, "mcp-iso-a-"+suffix, "MCP Iso A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tb, err := tenants.Create(ctx, "mcp-iso-b-"+suffix, "MCP Iso B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	var userA, userB string
	mustScope(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		u, err := (store.Users{}).Create(ctx, s, "mcp-a-"+suffix+"@example.com", "MCP A")
		if err == nil {
			userA = u.ID
		}
		return err
	})
	mustScope(ctx, t, pool, tb.ID, func(ctx context.Context, s tenancy.Scope) error {
		u, err := (store.Users{}).Create(ctx, s, "mcp-b-"+suffix+"@example.com", "MCP B")
		if err == nil {
			userB = u.ID
		}
		return err
	})

	mcp := store.NewMCPTokens(pool)
	hashA := crypto.Hash([]byte("mcp-a-" + suffix))
	hashB := crypto.Hash([]byte("mcp-b-" + suffix))
	idA, err := mcp.Create(ctx, ta.ID, userA, "tenant-a", hashA)
	if err != nil {
		t.Fatalf("create tenant A MCP token: %v", err)
	}
	idB, err := mcp.Create(ctx, tb.ID, userB, "tenant-b", hashB)
	if err != nil {
		t.Fatalf("create tenant B MCP token: %v", err)
	}

	// Pre-tenant authentication is the deliberate exception: the secret hash
	// selects its row, and that row establishes the tenant for later RBAC.
	if gotTenant, gotUser, err := mcp.Authenticate(ctx, hashB); err != nil || gotTenant != tb.ID || gotUser != userB {
		t.Fatalf("pre-tenant authenticate = (%q,%q,%v), want tenant B/user B", gotTenant, gotUser, err)
	}

	mustScope(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		var visible int
		if err := s.Q.QueryRow(ctx,
			"SELECT count(*) FROM mcp_tokens WHERE id IN ($1::uuid, $2::uuid)", idA, idB).Scan(&visible); err != nil {
			return err
		}
		if visible != 1 {
			t.Errorf("tenant A raw MCP-token count = %d, want exactly its own row", visible)
		}
		var foreignVisible bool
		if err := s.Q.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM mcp_tokens WHERE id = $1::uuid)", idB).Scan(&foreignVisible); err != nil {
			return err
		}
		if foreignVisible {
			t.Error("tenant A raw query could see tenant B MCP token (CROSS-TENANT LEAK)")
		}
		return nil
	})
}

func TestUnsetTenantAuthTablesFailClosed(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	fixture := seedPreTenantAuthFixture(ctx, t, pool)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin no-tenant transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		t.Fatalf("assume app role: %v", err)
	}

	var sessions, mcp, scim, enrollTokens, identities int
	if err := tx.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM sessions),
		  (SELECT count(*) FROM mcp_tokens),
		  (SELECT count(*) FROM scim_tokens),
		  (SELECT count(*) FROM agent_enroll_tokens),
		  (SELECT count(*) FROM agent_identities)`).
		Scan(&sessions, &mcp, &scim, &enrollTokens, &identities); err != nil {
		t.Fatalf("count auth tables without tenant GUC: %v", err)
	}
	if sessions != 0 || mcp != 0 || scim != 0 || enrollTokens != 0 || identities != 0 {
		t.Fatalf("direct app-role read without tenant GUC saw sessions=%d mcp=%d scim=%d enroll=%d identities=%d; want all zero",
			sessions, mcp, scim, enrollTokens, identities)
	}

	tag, err := tx.Exec(ctx, `UPDATE mcp_tokens SET name = name WHERE id = $1::uuid`, fixture.mcpIDA)
	if err != nil {
		t.Fatalf("update without tenant GUC: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("direct app-role update without tenant GUC touched %d rows, want zero", tag.RowsAffected())
	}

	var canRevokeEnroll, canListRevoked bool
	if err := tx.QueryRow(ctx, `
		SELECT
		  has_function_privilege(current_user, 'provider_revoke_agent_enroll_token(uuid)', 'EXECUTE'),
		  has_function_privilege(current_user, 'provider_list_revoked_agent_identities()', 'EXECUTE')`).
		Scan(&canRevokeEnroll, &canListRevoked); err != nil {
		t.Fatalf("inspect provider-function grants: %v", err)
	}
	if canRevokeEnroll || canListRevoked {
		t.Fatalf("application role can execute provider functions: revoke=%t list_revoked=%t", canRevokeEnroll, canListRevoked)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO mcp_tokens (tenant_id, user_id, name, token_hash)
		 VALUES ($1::uuid, $2::uuid, 'unscoped', $3)`,
		fixture.tenantA, fixture.userA, crypto.Hash([]byte("unscoped-"+fixture.suffix))); err == nil {
		t.Fatal("direct app-role insert without tenant GUC succeeded")
	}

	// break_glass_grants intentionally has no application-role table grant in
	// addition to its strict policy. Either zero rows or permission denied is
	// fail-closed; the latter aborts a transaction, so probe it separately.
	bgTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin no-tenant break-glass transaction: %v", err)
	}
	defer func() { _ = bgTx.Rollback(ctx) }()
	if _, err := bgTx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		t.Fatalf("assume app role for break-glass: %v", err)
	}
	var breakGlass int
	err = bgTx.QueryRow(ctx, `SELECT count(*) FROM break_glass_grants`).Scan(&breakGlass)
	if err == nil && breakGlass != 0 {
		t.Fatalf("direct app-role break-glass read without tenant GUC saw %d rows, want zero", breakGlass)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("direct app-role break-glass read failed unexpectedly: %v", err)
		}
	}
}

func TestPreTenantAuthFunctionsRemainNarrow(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	f := seedPreTenantAuthFixture(ctx, t, pool)

	mcp := store.NewMCPTokens(pool)
	for _, tc := range []struct {
		hash       []byte
		wantTenant string
		wantUser   string
	}{
		{f.mcpHashA, f.tenantA, f.userA},
		{f.mcpHashB, f.tenantB, f.userB},
	} {
		gotTenant, gotUser, err := mcp.Authenticate(ctx, tc.hash)
		if err != nil || gotTenant != tc.wantTenant || gotUser != tc.wantUser {
			t.Fatalf("MCP pre-tenant lookup = (%q,%q,%v), want (%q,%q,nil)",
				gotTenant, gotUser, err, tc.wantTenant, tc.wantUser)
		}
	}

	scim := store.NewScimTokens(pool)
	for _, tc := range []struct {
		hash       []byte
		wantTenant string
	}{
		{f.scimHashA, f.tenantA},
		{f.scimHashB, f.tenantB},
	} {
		gotTenant, err := scim.Authenticate(ctx, tc.hash)
		if err != nil || gotTenant != tc.wantTenant {
			t.Fatalf("SCIM pre-tenant lookup = (%q,%v), want (%q,nil)", gotTenant, err, tc.wantTenant)
		}
	}

	sessions := store.NewSessions(pool)
	var sourceSessionA *auth.Session
	for _, tc := range []struct {
		hash       []byte
		wantTenant string
		wantUser   string
	}{
		{f.sessionHashA, f.tenantA, f.userA},
		{f.sessionHashB, f.tenantB, f.userB},
	} {
		got, err := sessions.LookupByHash(ctx, tc.hash, time.Hour)
		if err != nil || got == nil || got.TenantID != tc.wantTenant || got.UserID != tc.wantUser {
			t.Fatalf("session pre-tenant lookup = (%+v,%v), want tenant=%s user=%s",
				got, err, tc.wantTenant, tc.wantUser)
		}
		if tc.wantTenant == f.tenantA {
			copied := *got
			copied.AuthorizationHash = append([]byte(nil), got.AuthorizationHash...)
			sourceSessionA = &copied
		}
	}
	if sourceSessionA == nil {
		t.Fatal("tenant A source session was not resolved")
	}

	rotatedHash := crypto.Hash([]byte("preauth-session-a-rotated-" + f.suffix))
	rotatedAuthorization := crypto.Hash([]byte("preauth-session-a-permissions-" + f.suffix))
	rotated, err := sessions.RotateByHash(ctx, f.sessionHashA, rotatedHash, auth.Session{
		TenantID:       f.tenantA,
		UserID:         f.userA,
		Email:          "attacker-controlled@example.com",
		DisplayName:    "Attacker Controlled",
		MFASatisfied:   true,
		TimeZone:       "Pacific/Kiritimati",
		Locale:         "attacker",
		TenantTimeZone: "Pacific/Kiritimati",
		TenantLocale:   "attacker",
		ExpiresAt:      sourceSessionA.ExpiresAt.Add(365 * 24 * time.Hour),
		CreatedAt:      sourceSessionA.CreatedAt.Add(-365 * 24 * time.Hour),
		LastActivityAt: time.Now().Add(365 * 24 * time.Hour),
		// AuthorizationHash is the sole caller-supplied session attribute the
		// permission-change rotation is intended to replace.
		AuthorizationHash: rotatedAuthorization,
	})
	if err != nil || !rotated {
		t.Fatalf("narrow session rotation = (%t,%v), want (true,nil)", rotated, err)
	}
	rotatedSession, err := sessions.LookupByHash(ctx, rotatedHash, time.Hour)
	if err != nil || rotatedSession == nil {
		t.Fatalf("lookup narrow session rotation = (%+v,%v)", rotatedSession, err)
	}
	if rotatedSession.TenantID != sourceSessionA.TenantID ||
		rotatedSession.UserID != sourceSessionA.UserID ||
		rotatedSession.Email != sourceSessionA.Email ||
		rotatedSession.DisplayName != sourceSessionA.DisplayName ||
		rotatedSession.MFASatisfied != sourceSessionA.MFASatisfied ||
		rotatedSession.TimeZone != sourceSessionA.TimeZone ||
		rotatedSession.Locale != sourceSessionA.Locale ||
		rotatedSession.TenantTimeZone != sourceSessionA.TenantTimeZone ||
		rotatedSession.TenantLocale != sourceSessionA.TenantLocale ||
		!rotatedSession.ExpiresAt.Equal(sourceSessionA.ExpiresAt) ||
		!rotatedSession.CreatedAt.Equal(sourceSessionA.CreatedAt) {
		t.Fatalf("rotation accepted caller-controlled identity/MFA/preferences/lifetime:\nsource=%+v\nrotated=%+v",
			sourceSessionA, rotatedSession)
	}
	if !bytes.Equal(rotatedSession.AuthorizationHash, rotatedAuthorization) {
		t.Fatalf("rotation authorization hash = %x, want %x", rotatedSession.AuthorizationHash, rotatedAuthorization)
	}
	if rotatedSession.LastActivityAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("rotation accepted caller-controlled future activity time: %s", rotatedSession.LastActivityAt)
	}
	if old, err := sessions.LookupByHash(ctx, f.sessionHashA, time.Hour); err != nil || old != nil {
		t.Fatalf("old session hash survived narrow rotation: (%+v,%v)", old, err)
	}

	enroll := store.NewEnrollTokens(pool)
	for _, tc := range []struct {
		hash       []byte
		usedBy     string
		wantTenant string
	}{
		{f.enrollHashA, "agent-a", f.tenantA},
		{f.enrollHashB, "agent-b", f.tenantB},
	} {
		gotTenant, _, err := enroll.Consume(ctx, tc.hash, tc.usedBy)
		if err != nil || gotTenant != tc.wantTenant {
			t.Fatalf("enrollment pre-tenant consume = (%q,%v), want (%q,nil)", gotTenant, err, tc.wantTenant)
		}
	}

	if revoked, err := enroll.Revoke(ctx, f.enrollRevokeIDA); err != nil || !revoked {
		t.Fatalf("provider enrollment-token revoke = (%t,%v), want (true,nil)", revoked, err)
	}
	if revoked, err := enroll.Revoke(ctx, f.enrollRevokeIDA); err != nil || revoked {
		t.Fatalf("provider enrollment-token re-revoke = (%t,%v), want (false,nil)", revoked, err)
	}
	mustScope(ctx, t, pool, f.tenantB, func(ctx context.Context, s tenancy.Scope) error {
		var untouched bool
		if err := s.Q.QueryRow(ctx,
			`SELECT revoked_at IS NULL FROM agent_enroll_tokens WHERE id = $1::uuid`,
			f.enrollKeepIDB).Scan(&untouched); err != nil {
			return err
		}
		if !untouched {
			t.Error("provider revoke of tenant A token changed tenant B token")
		}
		return nil
	})

	identities := store.NewAgentIdentities(pool)
	if _, _, err := identities.RevokeAgent(ctx, f.tenantA, "agent-a", "test"); err != nil {
		t.Fatalf("revoke tenant A identity: %v", err)
	}
	if _, _, err := identities.RevokeAgent(ctx, f.tenantB, "agent-b", "test"); err != nil {
		t.Fatalf("revoke tenant B identity: %v", err)
	}
	serials, spiffeIDs, err := identities.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("provider revoked-identity list: %v", err)
	}
	for _, want := range []string{f.serialA, f.serialB} {
		if !containsString(serials, want) {
			t.Errorf("provider revoked-identity serials missing %q", want)
		}
	}
	for _, want := range []string{f.spiffeA, f.spiffeB} {
		if !containsString(spiffeIDs, want) {
			t.Errorf("provider revoked-identity SPIFFE ids missing %q", want)
		}
	}

	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		var grants, tenantAGrants int
		if err := q.QueryRow(ctx,
			`SELECT count(*), count(*) FILTER (WHERE tenant_id = $3::uuid)
			   FROM break_glass_grants
			  WHERE id IN ($1::uuid, $2::uuid)`,
			f.breakGlassA, f.breakGlassB, f.tenantA).Scan(&grants, &tenantAGrants); err != nil {
			return err
		}
		if grants != 2 || tenantAGrants != 1 {
			t.Errorf("provider break-glass scope = (%d total,%d tenant A), want (2,1)", grants, tenantAGrants)
		}
		return nil
	}); err != nil {
		t.Fatalf("provider break-glass policy: %v", err)
	}

	if _, _, err := mcp.Authenticate(ctx, crypto.Hash([]byte("unknown-"+f.suffix))); !errors.Is(err, store.ErrInvalidToken) {
		t.Fatalf("unknown MCP hash = %v, want ErrInvalidToken", err)
	}
	if _, err := scim.Authenticate(ctx, crypto.Hash([]byte("unknown-scim-"+f.suffix))); !errors.Is(err, store.ErrInvalidScimToken) {
		t.Fatalf("unknown SCIM hash = %v, want ErrInvalidScimToken", err)
	}
	if got, err := sessions.LookupByHash(ctx, crypto.Hash([]byte("unknown-session-"+f.suffix)), time.Hour); err != nil || got != nil {
		t.Fatalf("unknown session hash = (%+v,%v), want (nil,nil)", got, err)
	}
}

type preTenantAuthFixture struct {
	suffix                         string
	tenantA, tenantB, userA, userB string
	mcpIDA                         string
	mcpHashA, mcpHashB             []byte
	scimHashA, scimHashB           []byte
	sessionHashA, sessionHashB     []byte
	enrollHashA, enrollHashB       []byte
	enrollRevokeIDA, enrollKeepIDB string
	serialA, serialB               string
	spiffeA, spiffeB               string
	breakGlassA, breakGlassB       string
}

func seedPreTenantAuthFixture(ctx context.Context, t *testing.T, pool *pgxpool.Pool) preTenantAuthFixture {
	t.Helper()
	f := preTenantAuthFixture{suffix: fmt.Sprintf("%d", time.Now().UnixNano())}
	tenants := store.NewTenants(pool)
	ta, err := tenants.Create(ctx, "preauth-a-"+f.suffix, "Pre-auth A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tb, err := tenants.Create(ctx, "preauth-b-"+f.suffix, "Pre-auth B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	f.tenantA, f.tenantB = ta.ID, tb.ID

	mustScope(ctx, t, pool, f.tenantA, func(ctx context.Context, s tenancy.Scope) error {
		u, err := (store.Users{}).Create(ctx, s, "preauth-a-"+f.suffix+"@example.com", "Pre-auth A")
		if err == nil {
			f.userA = u.ID
		}
		return err
	})
	mustScope(ctx, t, pool, f.tenantB, func(ctx context.Context, s tenancy.Scope) error {
		u, err := (store.Users{}).Create(ctx, s, "preauth-b-"+f.suffix+"@example.com", "Pre-auth B")
		if err == nil {
			f.userB = u.ID
		}
		return err
	})

	f.mcpHashA = crypto.Hash([]byte("preauth-mcp-a-" + f.suffix))
	f.mcpHashB = crypto.Hash([]byte("preauth-mcp-b-" + f.suffix))
	mcp := store.NewMCPTokens(pool)
	f.mcpIDA, err = mcp.Create(ctx, f.tenantA, f.userA, "tenant-a", f.mcpHashA)
	if err != nil {
		t.Fatalf("create tenant A MCP token: %v", err)
	}
	if _, err := mcp.Create(ctx, f.tenantB, f.userB, "tenant-b", f.mcpHashB); err != nil {
		t.Fatalf("create tenant B MCP token: %v", err)
	}

	f.scimHashA = crypto.Hash([]byte("preauth-scim-a-" + f.suffix))
	f.scimHashB = crypto.Hash([]byte("preauth-scim-b-" + f.suffix))
	scim := store.NewScimTokens(pool)
	if _, err := scim.Create(ctx, f.tenantA, "tenant-a", f.scimHashA); err != nil {
		t.Fatalf("create tenant A SCIM token: %v", err)
	}
	if _, err := scim.Create(ctx, f.tenantB, "tenant-b", f.scimHashB); err != nil {
		t.Fatalf("create tenant B SCIM token: %v", err)
	}

	f.sessionHashA = crypto.Hash([]byte("preauth-session-a-" + f.suffix))
	f.sessionHashB = crypto.Hash([]byte("preauth-session-b-" + f.suffix))
	sessions := store.NewSessions(pool)
	for _, tc := range []struct {
		hash, authHash   []byte
		tenantID, userID string
		email            string
	}{
		{f.sessionHashA, crypto.Hash([]byte("auth-a")), f.tenantA, f.userA, "preauth-a-" + f.suffix + "@example.com"},
		{f.sessionHashB, crypto.Hash([]byte("auth-b")), f.tenantB, f.userB, "preauth-b-" + f.suffix + "@example.com"},
	} {
		if err := sessions.Create(ctx, tc.hash, auth.Session{
			TenantID: tc.tenantID, UserID: tc.userID, Email: tc.email,
			ExpiresAt: time.Now().Add(time.Hour), AuthorizationHash: tc.authHash,
		}); err != nil {
			t.Fatalf("create session for tenant %s: %v", tc.tenantID, err)
		}
	}

	f.enrollHashA = crypto.Hash([]byte("preauth-enroll-a-" + f.suffix))
	f.enrollHashB = crypto.Hash([]byte("preauth-enroll-b-" + f.suffix))
	enroll := store.NewEnrollTokens(pool)
	if _, err := enroll.Create(ctx, f.tenantA, "", "tenant-a", "test", f.enrollHashA, time.Hour); err != nil {
		t.Fatalf("create tenant A enroll token: %v", err)
	}
	if _, err := enroll.Create(ctx, f.tenantB, "", "tenant-b", "test", f.enrollHashB, time.Hour); err != nil {
		t.Fatalf("create tenant B enroll token: %v", err)
	}
	f.enrollRevokeIDA, err = enroll.Create(ctx, f.tenantA, "", "tenant-a-revoke", "test",
		crypto.Hash([]byte("preauth-enroll-revoke-a-"+f.suffix)), time.Hour)
	if err != nil {
		t.Fatalf("create tenant A revocation candidate: %v", err)
	}
	f.enrollKeepIDB, err = enroll.Create(ctx, f.tenantB, "", "tenant-b-keep", "test",
		crypto.Hash([]byte("preauth-enroll-keep-b-"+f.suffix)), time.Hour)
	if err != nil {
		t.Fatalf("create tenant B revocation control: %v", err)
	}

	identities := store.NewAgentIdentities(pool)
	f.serialA = "preauth-serial-a-" + f.suffix
	f.serialB = "preauth-serial-b-" + f.suffix
	f.spiffeA = "spiffe://probectl/tenant/" + f.tenantA + "/agent/agent-a"
	f.spiffeB = "spiffe://probectl/tenant/" + f.tenantB + "/agent/agent-b"
	if err := identities.Record(ctx, f.tenantA, "agent-a", f.spiffeA,
		f.serialA, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatalf("record tenant A identity: %v", err)
	}
	if err := identities.Record(ctx, f.tenantB, "agent-b", f.spiffeB,
		f.serialB, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatalf("record tenant B identity: %v", err)
	}

	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		var operatorID string
		if err := q.QueryRow(ctx,
			`INSERT INTO provider_operators (email, name)
			 VALUES ($1, 'Pre-auth provider') RETURNING id::text`,
			"preauth-provider-"+f.suffix+"@example.com").Scan(&operatorID); err != nil {
			return err
		}
		for _, tc := range []struct {
			tenantID string
			id       *string
		}{
			{f.tenantA, &f.breakGlassA},
			{f.tenantB, &f.breakGlassB},
		} {
			if err := q.QueryRow(ctx,
				`INSERT INTO break_glass_grants (
					operator_id, tenant_id, reason, scope, granted_by, expires_at
				 ) VALUES ($1::uuid, $2::uuid, 'pre-tenant isolation test', 'read', 'test', now() + interval '1 hour')
				 RETURNING id::text`,
				operatorID, tc.tenantID).Scan(tc.id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed provider break-glass fixture: %v", err)
	}
	return f
}

func mustScope(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenantID string, fn func(context.Context, tenancy.Scope) error) {
	t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, fn); err != nil {
		t.Fatalf("InTenant(%s): %v", tenantID, err)
	}
}

func containsTenant(ts []store.Tenant, id string) bool {
	for i := range ts {
		if ts[i].ID == id {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
