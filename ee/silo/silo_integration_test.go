// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// The S-T2 named integration suite (live Postgres; ClickHouse legs are
// covered by the flowstore routing tests against httptest doubles):
//
//  1. a siloed tenant gets its own schema and its DATA IS PHYSICALLY
//     SEPARATED from the pooled tables,
//  2. pooled ↔ siloed parity: the same tenant-scoped operation behaves
//     identically under either model,
//  3. teardown fully removes the silo (and is idempotent),
//  4. catch-up brings a lagging silo up to a newer public shape.
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.PostgresDSN()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func mkTenant(t *testing.T, pool *pgxpool.Pool, slug, model, residency string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (slug, name, isolation_model, residency) VALUES ($1, $1, $2, $3)
		 ON CONFLICT (slug) DO UPDATE SET isolation_model = EXCLUDED.isolation_model
		 RETURNING id::text`, slug, model, residency).Scan(&id); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return id
}

func countIn(t *testing.T, pool *pgxpool.Pool, table, tenantID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, table), tenantID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestSiloedPhysicalSeparation(t *testing.T) {
	pool := itPool(t)
	// Register the pool first so it closes last: testing cleanups run LIFO, and
	// every schema/table cleanup below still needs a live connection.
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	siloedID := mkTenant(t, pool, "it-silo-"+stamp, "siloed", "")
	pooledID := mkTenant(t, pool, "it-pool-"+stamp, "pooled", "")
	schema := SchemaName(siloedID)

	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := prov.Provision(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		if err := prov.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
			t.Errorf("cleanup silo %s: %v", schema, err)
		}
	})

	// The schema exists and contains the tenant-owned tables.
	var schemaExists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)`, schema).Scan(&schemaExists); err != nil || !schemaExists {
		t.Fatalf("schema %s must exist: %v", schema, err)
	}
	for _, table := range []string{"tests", "agents", "audit_events"} {
		var ok bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2)`,
			schema, table).Scan(&ok); err != nil || !ok {
			t.Fatalf("silo must contain %s: %v", table, err)
		}
	}
	// Provider fleet capabilities are aggregate views over public agent rows,
	// not tenant-owned base tables. Copying either view with CREATE TABLE LIKE
	// would create an unclassified silo table and break lifecycle parity.
	for _, providerView := range []string{
		"provider_agent_fleet_counts",
		"provider_agent_fleet_versions",
	} {
		var copied bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM information_schema.tables
			    WHERE table_schema = $1 AND table_name = $2
			      AND table_type = 'BASE TABLE'
			 )`, schema, providerView).Scan(&copied); err != nil {
			t.Fatalf("inspect provider view %s in silo: %v", providerView, err)
		}
		if copied {
			t.Fatalf("provider aggregate view %s was copied as a tenant table", providerView)
		}
	}

	// Route through the real registry router (fail-closed semantics included).
	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })
	if _, err := router.TargetsFor(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("unknown tenant must fail closed under the registry-backed router: %v", err)
	}

	// The same tenant-scoped write for both tenants — THE parity operation.
	insertTest := func(tenantID, name string) error {
		ctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		return tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx,
				`INSERT INTO tests (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
				 VALUES ($1, $2, 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)`,
				tenantID, name)
			return err
		})
	}
	listTests := func(tenantID string) (int, error) {
		n := 0
		ctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM tests`).Scan(&n)
		})
		return n, err
	}

	if err := insertTest(siloedID, "silo-probe"); err != nil {
		t.Fatalf("siloed insert: %v", err)
	}
	if err := insertTest(pooledID, "pool-probe"); err != nil {
		t.Fatalf("pooled insert: %v", err)
	}

	// PHYSICAL separation: the siloed tenant's row lives in ITS schema's
	// table; the pooled table holds ZERO rows for it — and vice versa.
	if n := countIn(t, pool, "public.tests", siloedID); n != 0 {
		t.Fatalf("siloed tenant's data leaked into the pooled table: %d rows", n)
	}
	if n := countIn(t, pool, schema+".tests", siloedID); n != 1 {
		t.Fatalf("siloed tenant's data missing from its silo: %d rows", n)
	}
	if n := countIn(t, pool, "public.tests", pooledID); n != 1 {
		t.Fatalf("pooled tenant's data missing from the pooled table: %d rows", n)
	}

	// PARITY: the same read behaves identically under both models.
	for _, tc := range []struct {
		id   string
		want int
	}{{siloedID, 1}, {pooledID, 1}} {
		if n, err := listTests(tc.id); err != nil || n != tc.want {
			t.Fatalf("parity read for %s: n=%d err=%v", tc.id, n, err)
		}
	}

	// Defense-in-depth inside the silo: RLS still scopes by the GUC — a
	// query bound to ANOTHER tenant cannot see the silo rows even when
	// (hypothetically) routed into the schema.
	var crossCount int
	err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.tests WHERE tenant_id != $1`, siloedID).Scan(&crossCount)
	if err != nil || crossCount != 0 {
		t.Fatalf("foreign rows in the silo: %d %v", crossCount, err)
	}

	// Router truth: targets + bus namespaces.
	targets, err := router.TargetsFor(ctx, siloedID)
	if err != nil || targets.PGSchema != schema || targets.CHDatabase == "" || targets.BusNamespace == "" {
		t.Fatalf("siloed targets: %+v %v", targets, err)
	}
	ns, err := router.BusNamespaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range ns {
		if n == targets.BusNamespace {
			found = true
		}
	}
	if !found {
		t.Fatalf("bus namespaces missing the siloed tenant: %v", ns)
	}
	// DPR-049: the pooled tenant owns a lane as well — strict-lane mode
	// refuses agent-published planes on the shared lane for every tenant.
	byNS, err := router.BusNamespaceTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pooledListed := false
	for n, id := range byNS {
		if id == pooledID && strings.HasPrefix(n, "t-") {
			pooledListed = true
		}
	}
	if !pooledListed {
		t.Fatalf("bus namespaces missing the pooled tenant %s: %v", pooledID, byNS)
	}

	// CATCH-UP: simulate a later migration adding a tenant-owned table +
	// a column, then prove catch-up propagates both into the silo.
	newPlane := "it_newplane_" + stamp
	extraColumn := "it_extra_" + stamp
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)`, newPlane)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, newPlane)); err != nil {
			t.Errorf("cleanup public test table %s: %v", newPlane, err)
		}
	})
	if _, err := pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE tests ADD COLUMN IF NOT EXISTS %s text NOT NULL DEFAULT ''`, extraColumn)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE tests DROP COLUMN IF EXISTS %s`, extraColumn)); err != nil {
			t.Errorf("cleanup public test column %s: %v", extraColumn, err)
		}
	})

	drift, err := prov.driftFor(ctx, siloedID)
	if err != nil || drift.empty() {
		t.Fatalf("drift must be visible: %+v %v", drift, err)
	}
	if err := prov.CatchUp(ctx, siloedID); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	drift, err = prov.driftFor(ctx, siloedID)
	if err != nil || !drift.empty() {
		t.Fatalf("post-catch-up drift must be empty: %+v %v", drift, err)
	}

	// TEARDOWN: the schema is fully removed; pooled data is untouched;
	// re-running teardown is safe (idempotent).
	if err := prov.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)`, schema).Scan(&schemaExists); err != nil || schemaExists {
		t.Fatalf("schema must be gone after teardown: %v", err)
	}
	if err := prov.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("teardown must be idempotent: %v", err)
	}
	if n := countIn(t, pool, "public.tests", pooledID); n != 1 {
		t.Fatalf("teardown must not touch pooled data: %d", n)
	}
}

// TestPreTenantCredentialsRouteIntoSilos is the bounded real-Postgres
// regression for the awkward edge where a bearer hash has to identify its
// tenant before InTenant can select that tenant's physical schema. Tenant A is
// pooled and tenant B is siloed. The same production stores must authenticate,
// rotate/replace, consume, and revoke both tenants without copying detailed
// identity/session rows back into public.
func TestPreTenantCredentialsRouteIntoSilos(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())

	pooledID := mkTenant(t, pool, "pretenant-pool-"+stamp, "pooled", "")
	siloedID := mkTenant(t, pool, "pretenant-silo-"+stamp, "siloed", "")
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := prov.Provision(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision silo: %v", err)
	}
	t.Cleanup(func() {
		if err := prov.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
			t.Errorf("cleanup silo: %v", err)
		}
	})
	schema := SchemaName(siloedID)

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	createUser := func(tenantID, label string) string {
		t.Helper()
		var userID string
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				user, err := (store.Users{}).Create(
					ctx, sc, label+"-"+stamp+"@example.com", label,
				)
				if err == nil {
					userID = user.ID
				}
				return err
			},
		)
		if err != nil {
			t.Fatalf("create %s user: %v", label, err)
		}
		return userID
	}
	pooledUser := createUser(pooledID, "pooled")
	siloedUser := createUser(siloedID, "siloed")
	tokenHash := func(kind, tenant string) []byte {
		return crypto.Hash([]byte(kind + "-" + tenant + "-" + stamp))
	}

	sessions := store.NewSessions(pool)
	sessionHashes := map[string][]byte{
		pooledID: tokenHash("session", pooledID),
		siloedID: tokenHash("session", siloedID),
	}
	for tenantID, userID := range map[string]string{pooledID: pooledUser, siloedID: siloedUser} {
		if err := sessions.Create(ctx, sessionHashes[tenantID], auth.Session{
			TenantID: tenantID, UserID: userID,
			Email:     tenantID + "@example.com",
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create session for %s: %v", tenantID, err)
		}
		got, err := sessions.LookupByHash(ctx, sessionHashes[tenantID], time.Hour)
		if err != nil || got == nil || got.TenantID != tenantID || got.UserID != userID {
			t.Errorf("lookup session for %s = (%+v, %v)", tenantID, got, err)
		}
	}

	rotatedHash := tokenHash("session-rotated", siloedID)
	siloedSession, err := sessions.LookupByHash(ctx, sessionHashes[siloedID], time.Hour)
	if err != nil || siloedSession == nil {
		t.Fatalf("load silo session for rotation: session=%+v err=%v", siloedSession, err)
	}
	if rotated, err := sessions.RotateByHash(
		ctx, sessionHashes[siloedID], rotatedHash, *siloedSession,
	); err != nil || !rotated {
		t.Errorf("rotate silo session: rotated=%t err=%v", rotated, err)
	}
	if old, err := sessions.LookupByHash(ctx, sessionHashes[siloedID], time.Hour); err != nil || old != nil {
		t.Errorf("old silo session after rotation = (%+v, %v)", old, err)
	}
	if got, err := sessions.LookupByHash(ctx, rotatedHash, time.Hour); err != nil || got == nil || got.TenantID != siloedID {
		t.Errorf("rotated silo session = (%+v, %v)", got, err)
	}

	// A fresh IdP authentication may race in two callback handlers. Exactly one
	// successor may survive, and its detailed row must stay in the silo.
	predecessorHash := tokenHash("session-predecessor", siloedID)
	if err := sessions.Create(ctx, predecessorHash, auth.Session{
		TenantID: siloedID, UserID: siloedUser,
		Email:     "siloed-" + stamp + "@example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create replacement predecessor: %v", err)
	}
	successorHashes := [][]byte{
		tokenHash("session-successor-a", siloedID),
		tokenHash("session-successor-b", siloedID),
	}
	type replaceResult struct {
		created bool
		err     error
	}
	results := make([]replaceResult, len(successorHashes))
	var wg sync.WaitGroup
	for i := range successorHashes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].created, results[i].err = sessions.ReplaceAuthenticatedByHash(
				ctx, predecessorHash, nil, successorHashes[i],
				auth.Session{
					TenantID: siloedID, UserID: siloedUser,
					Email:     "fresh-siloed-" + stamp + "@example.com",
					ExpiresAt: time.Now().Add(2 * time.Hour),
				},
			)
		}(i)
	}
	wg.Wait()
	winners := 0
	for i, result := range results {
		if result.err != nil {
			t.Errorf("replace contender %d: %v", i, result.err)
		}
		if result.created {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("authenticated replacement winners = %d, want 1", winners)
	}
	if got, err := sessions.LookupByHash(ctx, predecessorHash, time.Hour); err != nil || got != nil {
		t.Errorf("replaced silo predecessor = (%+v, %v), want inactive", got, err)
	}
	resolvedSuccessors := 0
	for _, hash := range successorHashes {
		if got, err := sessions.LookupByHash(ctx, hash, time.Hour); err != nil {
			t.Errorf("lookup replacement successor: %v", err)
		} else if got != nil {
			resolvedSuccessors++
		}
	}
	if resolvedSuccessors != 1 {
		t.Errorf("resolvable authenticated successors = %d, want 1", resolvedSuccessors)
	}

	mcp := store.NewMCPTokens(pool)
	mcpHashes := map[string][]byte{
		pooledID: tokenHash("mcp", pooledID),
		siloedID: tokenHash("mcp", siloedID),
	}
	mcpIDs := map[string]string{}
	for tenantID, userID := range map[string]string{pooledID: pooledUser, siloedID: siloedUser} {
		id, err := mcp.Create(ctx, tenantID, userID, "integration", mcpHashes[tenantID])
		if err != nil {
			t.Fatalf("create MCP token for %s: %v", tenantID, err)
		}
		mcpIDs[tenantID] = id
		gotTenant, gotUser, err := mcp.Authenticate(ctx, mcpHashes[tenantID])
		if err != nil || gotTenant != tenantID || gotUser != userID {
			t.Errorf("authenticate MCP for %s = (%s, %s, %v)", tenantID, gotTenant, gotUser, err)
		}
	}
	if err := mcp.RevokeForUser(ctx, siloedID, siloedUser); err != nil {
		t.Errorf("revoke silo MCP token: %v", err)
	}
	if _, _, err := mcp.Authenticate(ctx, mcpHashes[siloedID]); !errors.Is(err, store.ErrInvalidToken) {
		t.Errorf("revoked silo MCP token = %v, want ErrInvalidToken", err)
	}
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(siloedID)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			deleted, err := store.DeleteSubjectCredentialLocatorsScoped(
				ctx, sc, nil,
				[]string{mcpIDs[siloedID], mcpIDs[pooledID]},
			)
			if err != nil {
				return err
			}
			if deleted != 1 {
				t.Errorf("tenant-B locator erasure deleted %d rows, want 1", deleted)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("tenant-scoped locator erasure: %v", err)
	}
	if gotTenant, gotUser, err := mcp.Authenticate(ctx, mcpHashes[pooledID]); err != nil ||
		gotTenant != pooledID || gotUser != pooledUser {
		t.Errorf(
			"tenant-B locator erasure touched pooled decoy = (%s, %s, %v)",
			gotTenant, gotUser, err,
		)
	}

	scim := store.NewScimTokens(pool)
	scimHashes := map[string][]byte{
		pooledID: tokenHash("scim", pooledID),
		siloedID: tokenHash("scim", siloedID),
	}
	var siloScimID string
	for tenantID, hash := range scimHashes {
		id, err := scim.Create(ctx, tenantID, "integration", hash)
		if err != nil {
			t.Fatalf("create SCIM token for %s: %v", tenantID, err)
		}
		if tenantID == siloedID {
			siloScimID = id
		}
		if got, err := scim.Authenticate(ctx, hash); err != nil || got != tenantID {
			t.Errorf("authenticate SCIM for %s = (%s, %v)", tenantID, got, err)
		}
	}
	if err := scim.Revoke(ctx, siloedID, siloScimID); err != nil {
		t.Errorf("revoke silo SCIM token: %v", err)
	}
	if _, err := scim.Authenticate(ctx, scimHashes[siloedID]); !errors.Is(err, store.ErrInvalidScimToken) {
		t.Errorf("revoked silo SCIM token = %v, want ErrInvalidScimToken", err)
	}

	otlp := store.NewOTLPTokens(pool)
	otlpHashes := map[string][]byte{
		pooledID: tokenHash("otlp", pooledID),
		siloedID: tokenHash("otlp", siloedID),
	}
	var siloOTLPID string
	for tenantID, hash := range otlpHashes {
		id, err := otlp.Create(ctx, tenantID, "integration", hash)
		if err != nil {
			t.Fatalf("create OTLP token for %s: %v", tenantID, err)
		}
		if tenantID == siloedID {
			siloOTLPID = id
		}
		if got, err := otlp.Authenticate(ctx, hash); err != nil || got != tenantID {
			t.Errorf("authenticate OTLP for %s = (%s, %v)", tenantID, got, err)
		}
	}
	if err := otlp.Revoke(ctx, siloedID, siloOTLPID); err != nil {
		t.Errorf("revoke silo OTLP token: %v", err)
	}
	if _, err := otlp.Authenticate(ctx, otlpHashes[siloedID]); !errors.Is(err, store.ErrInvalidOTLPToken) {
		t.Errorf("revoked silo OTLP token = %v, want ErrInvalidOTLPToken", err)
	}

	enroll := store.NewEnrollTokens(pool)
	for tenantID := range map[string]bool{pooledID: true, siloedID: true} {
		hash := tokenHash("enroll-consume", tenantID)
		if _, err := enroll.Create(ctx, tenantID, "", "integration", "test", hash, time.Hour); err != nil {
			t.Fatalf("create enroll token for %s: %v", tenantID, err)
		}
		if got, _, err := enroll.Consume(ctx, hash, "agent-"+stamp); err != nil || got != tenantID {
			t.Errorf("consume enroll token for %s = (%s, %v)", tenantID, got, err)
		}
	}
	revokedEnrollHash := tokenHash("enroll-revoked", siloedID)
	revokedEnrollID, err := enroll.Create(
		ctx, siloedID, "", "revoke", "test", revokedEnrollHash, time.Hour,
	)
	if err != nil {
		t.Fatalf("create revocable silo enroll token: %v", err)
	}
	if revoked, err := enroll.Revoke(ctx, revokedEnrollID); err != nil || !revoked {
		t.Errorf("revoke silo enroll token: revoked=%t err=%v", revoked, err)
	}
	if _, _, err := enroll.Consume(ctx, revokedEnrollHash, "agent-"+stamp); !errors.Is(err, store.ErrEnrollTokenInvalid) {
		t.Errorf("consume revoked silo enroll token = %v, want ErrEnrollTokenInvalid", err)
	}

	identities := store.NewAgentIdentities(pool)
	pooledSerial := "pooled-" + stamp
	siloedSerial := "siloed-" + stamp
	pooledSPIFFE := "spiffe://probectl/tenant/" + pooledID + "/agent/pooled"
	siloedSPIFFE := "spiffe://probectl/tenant/" + siloedID + "/agent/siloed"
	if err := identities.Record(ctx, pooledID, "pooled", pooledSPIFFE, pooledSerial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatalf("record pooled identity: %v", err)
	}
	if err := identities.Record(ctx, siloedID, "siloed", siloedSPIFFE, siloedSerial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatalf("record silo identity: %v", err)
	}
	if _, _, err := identities.RevokeAgent(ctx, siloedID, "siloed", "integration"); err != nil {
		t.Errorf("revoke silo identity: %v", err)
	}
	serials, spiffes, err := identities.ListRevoked(ctx)
	if err != nil {
		t.Errorf("list revoked identities: %v", err)
	}
	if !containsString(serials, siloedSerial) || !containsString(spiffes, siloedSPIFFE) {
		t.Errorf("silo revocation absent from deployment deny-list: serials=%v spiffes=%v", serials, spiffes)
	}
	if containsString(serials, pooledSerial) || containsString(spiffes, pooledSPIFFE) {
		t.Errorf("unrevoked pooled decoy entered deny-list: serials=%v spiffes=%v", serials, spiffes)
	}

	// Simulate an existing silo restored from an older backup whose detailed
	// rows survived but whose newer global locator/revocation metadata did not.
	// CatchUp must rebuild only the opaque shared metadata from the silo.
	if _, err := pool.Exec(ctx,
		`DELETE FROM credential_locators
		  WHERE credential_kind = 'session' AND token_hash = $1`,
		rotatedHash,
	); err != nil {
		t.Fatalf("remove locator for catch-up rehearsal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM agent_identity_revocations
		  WHERE tenant_id = $1 AND serial = $2`,
		siloedID, siloedSerial,
	); err != nil {
		t.Fatalf("remove revocation for catch-up rehearsal: %v", err)
	}
	if got, err := sessions.LookupByHash(ctx, rotatedHash, time.Hour); err != nil || got != nil {
		t.Fatalf("removed locator still resolved: session=%+v err=%v", got, err)
	}
	if err := prov.CatchUp(ctx, siloedID); err != nil {
		t.Fatalf("catch up pre-tenant metadata: %v", err)
	}
	if got, err := sessions.LookupByHash(ctx, rotatedHash, time.Hour); err != nil || got == nil || got.TenantID != siloedID {
		t.Errorf("catch-up did not restore silo session locator: session=%+v err=%v", got, err)
	}
	serials, spiffes, err = identities.ListRevoked(ctx)
	if err != nil {
		t.Errorf("list catch-up revocations: %v", err)
	}
	if !containsString(serials, siloedSerial) || !containsString(spiffes, siloedSPIFFE) {
		t.Errorf("catch-up did not restore silo revocation: serials=%v spiffes=%v", serials, spiffes)
	}

	// The credential details remain physically tenant-owned. The shared public
	// schema has tenant A's rows and zero tenant-B rows; tenant B's schema has
	// its own rows and RLS still hides them from tenant A.
	for _, table := range []string{
		"sessions", "mcp_tokens", "scim_tokens", "otlp_tokens",
		"agent_enroll_tokens", "agent_identities",
	} {
		if n := countIn(t, pool, "public."+table, siloedID); n != 0 {
			t.Errorf("silo credential details leaked into public.%s: %d", table, n)
		}
		if n := countIn(t, pool, schema+"."+table, siloedID); n == 0 {
			t.Errorf("silo credential details missing from %s.%s", schema, table)
		}
		if n := countIn(t, pool, "public."+table, pooledID); n == 0 {
			t.Errorf("pooled decoy credential missing from public.%s", table)
		}
	}
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(pooledID)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var n int
			if err := sc.Q.QueryRow(ctx,
				`SELECT count(*) FROM sessions WHERE tenant_id = $1`, siloedID,
			).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("pooled tenant observed silo session rows: %d", n)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("two-tenant RLS check: %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
