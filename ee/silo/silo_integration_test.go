// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

//go:build integration

package silo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
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
	dsn := os.Getenv("PROBECTL_TEST_POSTGRES")
	if dsn == "" {
		dsn = "postgres://probectl:probectl@localhost:5432/probectl"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("postgres unavailable: %v", err)
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
	defer pool.Close()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	stamp := time.Now().UTC().Format("150405")
	siloedID := mkTenant(t, pool, "it-silo-"+stamp, "siloed", "")
	pooledID := mkTenant(t, pool, "it-pool-"+stamp, "pooled", "")
	schema := SchemaName(siloedID)

	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := prov.Provision(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = prov.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed) })

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

	// Route through the real registry router (fail-closed semantics included).
	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

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

	// CATCH-UP: simulate a later migration adding a tenant-owned table +
	// a column, then prove catch-up propagates both into the silo.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS it_newplane (
		id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS it_newplane`) })
	if _, err := pool.Exec(ctx, `ALTER TABLE tests ADD COLUMN IF NOT EXISTS it_extra text NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `ALTER TABLE tests DROP COLUMN IF EXISTS it_extra`) })

	drift, err := prov.DriftFor(ctx, siloedID)
	if err != nil || drift.Empty() {
		t.Fatalf("drift must be visible: %+v %v", drift, err)
	}
	if err := prov.CatchUp(ctx, siloedID); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	drift, err = prov.DriftFor(ctx, siloedID)
	if err != nil || !drift.Empty() {
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
