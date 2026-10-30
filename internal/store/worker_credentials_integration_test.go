// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func workerRuntimePool(ctx context.Context, t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	connection := os.Getenv("PROBECTL_WORKER_CREDENTIAL_TEST_DATABASE_URL")
	var pool *pgxpool.Pool
	var err error
	if connection == "" {
		pool = workerTemporaryRuntimePool(ctx, t, admin)
	} else {
		pool, err = pgxpool.New(ctx, connection)
	}
	if err != nil {
		t.Fatal("worker runtime PostgreSQL configuration unavailable")
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "worker runtime PostgreSQL unavailable")
		return nil
	}
	var super, bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass); err != nil || super || bypass {
		t.Fatal("worker proof must use an actual NOSUPERUSER NOBYPASSRLS login")
	}
	return pool
}

// CI supplies the real TLS admin profile. Create an owned restricted LOGIN,
// rather than treating a superuser SET ROLE session as the runtime proof or
// skipping when a new test-only variable has not been exported.
func workerTemporaryRuntimePool(ctx context.Context, t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	random, err := crypto.Random(32)
	if err != nil {
		t.Fatal("runtime fixture entropy unavailable")
	}
	name := "probectl-qa-beta-worker-" + hex.EncodeToString(random[:8])
	passwordEntropy, err := crypto.Random(32)
	if err != nil {
		t.Fatal("runtime password entropy unavailable")
	}
	password := hex.EncodeToString(passwordEntropy)
	role := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD '`+password+`'`); err != nil {
		t.Fatal("owned restricted runtime LOGIN could not be created")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DROP ROLE `+role); err != nil {
			t.Error("owned runtime LOGIN cleanup failed")
		}
	})
	for _, statement := range []string{`GRANT probectl_app TO ` + role, `GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("owned runtime LOGIN membership unavailable")
		}
	}
	config := admin.Config().Copy()
	config.ConnConfig.User, config.ConnConfig.Password = name, password
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("owned runtime LOGIN connection unavailable")
	}
	return pool
}

func workerReadOnlyCredentials(ctx context.Context, t *testing.T, pool *pgxpool.Pool) WorkerCredentials {
	t.Helper()
	config := pool.Config().Copy()
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readonly, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("read-only runtime profile unavailable")
	}
	t.Cleanup(readonly.Close)
	reader, err := NewWorkerCredentials(readonly, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func workerCaptureTestRef(t *testing.T, kind auth.WorkerCredentialKind, tenant, owner, id string, hash []byte) auth.WorkerCredentialRef {
	t.Helper()
	ref, err := auth.CaptureWorkerCredential(kind, tenant, owner, id, hash)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestWorkerCredentialsPostgresRuntimeIsolationRotationAndNoActivityTouch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin := setup(ctx, t)
	t.Cleanup(admin.Close)
	pool := workerRuntimePool(ctx, t, admin)
	reader, err := NewWorkerCredentials(pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tenant, owner := sessionCleanupIdentity(ctx, t, admin, "worker-blue")
	foreignTenant, foreignOwner := sessionCleanupIdentity(ctx, t, admin, "worker-red")
	var otherOwner string
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (Users{}).Create(ctx, sc, "second-worker-owner@example.test", "Second worker owner")
		if err == nil {
			otherOwner = user.ID
		}
		return err
	})
	tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
	foreignCtx := tenancy.WithTenant(ctx, tenancy.ID(foreignTenant))
	sessions := NewSessions(admin)
	createSession := func(tenant, owner, label string) (*auth.Session, []byte, auth.WorkerCredentialRef) {
		t.Helper()
		hash := crypto.Hash([]byte(label + tenant + owner))
		if err := sessions.Create(ctx, hash, auth.Session{TenantID: tenant, UserID: owner, Email: "worker@example.test", ExpiresAt: time.Now().Add(2 * time.Hour), MFASatisfied: true}); err != nil {
			t.Fatal("create owned session fixture", err)
		}
		session, err := sessions.LookupByHash(ctx, hash, time.Hour)
		if err != nil || session == nil {
			t.Fatal("authenticate owned fixture before reference capture", err)
		}
		return session, hash, workerCaptureTestRef(t, auth.WorkerCredentialSession, tenant, owner, session.ID, hash)
	}
	session, hash, ref := createSession(tenant, owner, "owned-session-")
	foreign, _, foreignRef := createSession(foreignTenant, foreignOwner, "foreign-session-")
	_, _, otherRef := createSession(tenant, otherOwner, "second-owner-session-")
	var before time.Time
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT last_activity_at FROM sessions WHERE id=$1`, session.ID).Scan(&before)
	})
	for range 3 {
		got, err := reader.RevalidateSession(tenantCtx, tenant, owner, ref)
		if err != nil || got == nil || got.ID != session.ID || !got.MFASatisfied || !got.LastActivityAt.Equal(before) {
			t.Fatal("live exact session metadata missing or activity extended", err)
		}
	}
	var after time.Time
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT last_activity_at FROM sessions WHERE id=$1`, session.ID).Scan(&after)
	})
	if !after.Equal(before) {
		t.Fatal("worker refreshed browser idle activity")
	}
	for _, test := range []struct {
		ctx           context.Context
		tenant, owner string
		ref           auth.WorkerCredentialRef
	}{
		{tenantCtx, tenant, owner, foreignRef},
		{tenantCtx, tenant, owner, otherRef},
		{tenantCtx, tenant, otherOwner, ref},
		{foreignCtx, foreignTenant, foreignOwner, ref},
		{ctx, tenant, owner, ref},
		{foreignCtx, tenant, owner, ref},
	} {
		if got, err := reader.RevalidateSession(test.ctx, test.tenant, test.owner, test.ref); !errors.Is(err, auth.ErrWorkerCredentialInvalid) || got != nil {
			t.Fatal("foreign/missing context or owner obtained credential metadata", err)
		}
	}
	wire, err := ref.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)-1] ^= 1
	tampered, err := auth.DecodeWorkerCredentialRef(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reader.RevalidateSession(tenantCtx, tenant, owner, tampered); !errors.Is(err, auth.ErrWorkerCredentialInvalid) || got != nil {
		t.Fatal("stored-row lookup skipped the exact fingerprint", err)
	}
	for _, table := range []string{"sessions", "mcp_tokens", "users"} {
		var enabled, forced bool
		if err := admin.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=to_regclass($1)`, table).Scan(&enabled, &forced); err != nil || !enabled || !forced {
			t.Fatal("credential proof requires FORCE RLS on every joined tenant table")
		}
	}
	// No tenant predicate: the restricted runtime role and storage RLS must
	// hide the other tenant even before the repository's explicit predicates.
	if err := tenancy.InTenant(tenantCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id=$1`, foreign.ID).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("session RLS exposed a foreign origin without a tenant predicate")
		}
		return nil
	}); err != nil {
		t.Fatal("runtime session isolation query failed", err)
	}
	// A changed hash on the SAME session ID must invalidate its predecessor.
	newHash := crypto.Hash([]byte("rotated-worker-" + tenant))
	rotated, err := sessions.RotateByHash(ctx, hash, newHash, *session)
	if err != nil || !rotated {
		t.Fatal("rotate exact session fixture", err)
	}
	if _, err := reader.RevalidateSession(tenantCtx, tenant, owner, ref); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("worker borrowed the successor on a stable session row ID", err)
	}
	newRef := workerCaptureTestRef(t, auth.WorkerCredentialSession, tenant, owner, session.ID, newHash)
	if _, err := reader.RevalidateSession(tenantCtx, tenant, owner, newRef); err != nil {
		t.Fatal("independently admitted successor reference failed", err)
	}
	for _, mutation := range []string{
		`UPDATE sessions SET last_activity_at=now()-interval '2 hours' WHERE id=$1`,
		`UPDATE sessions SET expires_at=now()-interval '1 second' WHERE id=$1`,
		`UPDATE sessions SET replaced_at=now() WHERE id=$1`,
	} {
		inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, mutation, session.ID)
			return err
		})
		if _, err := reader.RevalidateSession(tenantCtx, tenant, owner, newRef); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
			t.Fatal("idle/absolute-expired/replaced session stayed live", err)
		}
		inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE sessions SET last_activity_at=now(),expires_at=now()+interval '2 hours',replaced_at=NULL WHERE id=$1`, session.ID)
			return err
		})
	}
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (Users{}).updateStatus(ctx, sc, owner, "disabled")
		return err
	})
	if _, err := reader.RevalidateSession(tenantCtx, tenant, owner, newRef); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("inactive session owner remained authorized", err)
	}
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (Users{}).updateStatus(ctx, sc, owner, "active")
		return err
	})
	readonlySession := workerReadOnlyCredentials(ctx, t, pool)
	if _, err := readonlySession.RevalidateSession(tenantCtx, tenant, owner, newRef); err != nil {
		t.Fatal("read-only session verification attempted a write", err)
	}
	if err := sessions.DeleteByHash(ctx, newHash); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.RevalidateSession(tenantCtx, tenant, owner, newRef); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("deleted origin reference stayed live", err)
	}
}

func TestWorkerCredentialsPostgresCurrentScopesExpiryRevocationAndReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin := setup(ctx, t)
	t.Cleanup(admin.Close)
	pool := workerRuntimePool(ctx, t, admin)
	reader, err := NewWorkerCredentials(pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tenant, owner := sessionCleanupIdentity(ctx, t, admin, "worker-token-blue")
	red, redOwner := sessionCleanupIdentity(ctx, t, admin, "worker-token-red")
	tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
	tokens := NewMCPTokens(admin)
	hash := crypto.Hash([]byte("owned-worker-token-" + tenant))
	id, err := tokens.CreateWithLifetime(ctx, tenant, owner, "worker", hash, time.Now().Add(time.Hour), []string{"flow.read"})
	if err != nil {
		t.Fatal(err)
	}
	ref := workerCaptureTestRef(t, auth.WorkerCredentialMCP, tenant, owner, id, hash)
	redHash := crypto.Hash([]byte("red-worker-token-" + red))
	redID, err := tokens.CreateWithLifetime(ctx, red, redOwner, "red-worker", redHash, time.Now().Add(time.Hour), []string{"flow.read"})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		state, err := reader.RevalidateMCP(tenantCtx, tenant, owner, ref)
		if err != nil || state.TokenID != id || state.TenantID != tenant || state.UserID != owner || state.FirstUse || !reflect.DeepEqual(state.Scopes, []string{"flow.read"}) {
			t.Fatal("worker lost current scopes or invented first-use authentication", err)
		}
	}
	var lastUsed *time.Time
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT last_used_at FROM mcp_tokens WHERE id=$1`, id).Scan(&lastUsed)
	})
	if lastUsed != nil {
		t.Fatal("worker stamped an otherwise unused MCP credential")
	}
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE mcp_tokens SET scopes=$2 WHERE id=$1`, id, []string{"ai.query"})
		return err
	})
	state, err := reader.RevalidateMCP(tenantCtx, tenant, owner, ref)
	if err != nil || !reflect.DeepEqual(state.Scopes, []string{"ai.query"}) {
		t.Fatal("worker reused a cached scope snapshot", err)
	}
	if err := tenancy.InTenant(tenantCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM mcp_tokens WHERE id=$1`, redID).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("MCP RLS exposed another tenant's origin without a tenant predicate")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	providerErr := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		var count int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM mcp_tokens WHERE id=$1`, id).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("provider obtained an implicit credential read")
		}
		return nil
	})
	if providerErr != nil {
		var denied *pgconn.PgError
		if !errors.As(providerErr, &denied) || denied.Code != "42501" {
			t.Fatal("provider proof failed for a reason other than access refusal")
		}
	}
	ro := workerReadOnlyCredentials(ctx, t, pool)
	if _, err := ro.RevalidateMCP(tenantCtx, tenant, owner, ref); err != nil {
		t.Fatal("read-only worker verification attempted a write", err)
	}
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (Users{}).updateStatus(ctx, sc, owner, "disabled")
		return err
	})
	if _, err := reader.RevalidateMCP(tenantCtx, tenant, owner, ref); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("inactive MCP owner remained authorized", err)
	}
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (Users{}).updateStatus(ctx, sc, owner, "active")
		return err
	})

	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE mcp_tokens SET expires_at=now()-interval '1 second' WHERE id=$1`, id)
		return err
	})
	if _, err := reader.RevalidateMCP(tenantCtx, tenant, owner, ref); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("expired MCP origin remained live", err)
	}
	inTenant(ctx, t, admin, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE mcp_tokens SET expires_at=now()+interval '1 hour' WHERE id=$1`, id)
		return err
	})
	if found, err := tokens.RevokeByID(ctx, tenant, id); err != nil || !found {
		t.Fatal(err)
	}
	if _, err := reader.RevalidateMCP(tenantCtx, tenant, owner, ref); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("revoked MCP origin remained live", err)
	}
}

// The permission loader reads real current grants under RLS; no persisted
// Principal or test-auth bypass supplies the originating worker identity.
type workerCurrentPermissions struct{ pool *pgxpool.Pool }

func (p workerCurrentPermissions) ForUser(ctx context.Context, tenant, owner string) ([]auth.PermissionGrant, error) {
	var grants []auth.PermissionGrant
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		grants, err = (Permissions{}).ForSubject(ctx, sc, "user", owner)
		return err
	})
	return grants, err
}

func TestWorkerCredentialsPostgresAuthenticatedSessionCaptureAndPermissionRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin := setup(ctx, t)
	t.Cleanup(admin.Close)
	pool := workerRuntimePool(ctx, t, admin)
	reader, err := NewWorkerCredentials(pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tenant, owner := sessionCleanupIdentity(ctx, t, admin, "worker-authenticated-capture")
	scoped := tenancy.WithTenant(ctx, tenancy.ID(tenant))
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal("owned session HMAC entropy unavailable")
	}
	mgr := auth.NewManager(NewSessions(pool), time.Hour, true, key)
	token, err := mgr.Issue(ctx, auth.Session{TenantID: tenant, UserID: owner, MFASatisfied: true,
		AuthorizationHash: []byte("owned stale permission fingerprint to require the existing rotation")})
	if err != nil {
		t.Fatal("issue real runtime session", err)
	}
	request := func(value string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://localhost/v1/explorer/flow/questions", nil).WithContext(ctx)
		r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: value})
		return r
	}
	authn := auth.NewAuthenticator(mgr, workerCurrentPermissions{pool})
	principal, err := authn.Resolve(request(token))
	if err != nil || principal == nil {
		t.Fatal("authenticate real session before queue capture", err)
	}
	original, err := auth.WorkerCredentialFromPrincipal(principal)
	if err != nil {
		t.Fatal("real session has no exact origin", err)
	}
	if !mgr.WorkerCredentialPolicyMatches(original) || auth.NewManager(NewSessions(pool), time.Hour, true, crypto.Hash([]byte("different owned policy key"))).WorkerCredentialPolicyMatches(original) {
		t.Fatal("real accepted origin did not fence its authenticating Manager policy")
	}

	state, err := reader.RevalidateSession(scoped, tenant, owner, original)
	if err != nil || state == nil || !state.MFASatisfied {
		t.Fatal("captured session not independently verifiable", err)
	}
	if !original.MatchesStored(auth.WorkerCredentialSession, tenant, owner, state.ID, crypto.Sign(key, []byte(token))) {
		t.Fatal("real origin did not use accepted HMAC hash")
	}
	successor, replacement, err := authn.ResolveAndRotate(request(token))
	if err != nil || successor == nil || replacement == "" {
		t.Fatal("real permission refresh did not rotate", err)
	}
	if _, err := reader.RevalidateSession(scoped, tenant, owner, original); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("original queued job borrowed the refreshed session", err)
	}
	updated, err := auth.WorkerCredentialFromPrincipal(successor)
	if err != nil {
		t.Fatal(err)
	}
	current, err := reader.RevalidateSession(scoped, tenant, owner, updated)
	if err != nil || current == nil || current.ID != state.ID || !updated.MatchesStored(auth.WorkerCredentialSession, tenant, owner, state.ID, crypto.Sign(key, []byte(replacement))) {
		t.Fatal("authentication rotation captured the wrong successor", err)
	}
	before := current.LastActivityAt
	for range 3 {
		current, err = reader.RevalidateSession(scoped, tenant, owner, updated)
		if err != nil || current == nil || !current.LastActivityAt.Equal(before) {
			t.Fatal("worker extended activity after successful admission", err)
		}
	}
	if stale, err := authn.Resolve(request(token)); err != nil || stale != nil {
		t.Fatal("old browser token remained accepted after rotation", err)
	}
	if err := mgr.Revoke(ctx, replacement); err != nil {
		t.Fatal("revoke owned current session", err)
	}
	if _, err := reader.RevalidateSession(scoped, tenant, owner, updated); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("revoked accepted origin remained usable", err)
	}
}
