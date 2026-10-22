// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package testsync_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsync"
	"github.com/ctlplne/probectl/migrations"
)

func dsn() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl@localhost:5432/postgres?sslmode=disable"
}

func setup(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func inTenant(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenant string, fn func(context.Context, tenancy.Scope) error) {
	t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
		t.Fatalf("InTenant(%s): %v", tenant, err)
	}
}

func version(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenant string) uint64 {
	t.Helper()
	var v uint64
	inTenant(ctx, t, pool, tenant, func(ctx context.Context, s tenancy.Scope) error {
		var err error
		v, err = (store.TestSets{}).Version(ctx, s)
		return err
	})
	return v
}

func createTest(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenant, name, target string, enabled bool) string {
	t.Helper()
	var id string
	inTenant(ctx, t, pool, tenant, func(ctx context.Context, s tenancy.Scope) error {
		tt, err := (store.Tests{}).Create(ctx, s, store.TestInput{
			Name: name, Type: "http", Target: target, IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: enabled,
		})
		if err != nil {
			return err
		}
		id = tt.ID
		return nil
	})
	return id
}

// TestSourceIsTenantScopedAndVersioned is the G9 storage-layer isolation proof
// (docs/guardrails.md G7-1): a tenant's signed bundle carries only its own
// enabled tests, its version moves on every create/update/delete of ITS tests
// and never on another tenant's, and the version table is FORCE-RLS scoped so
// a predicate-free read sees only the caller's row.
func TestSourceIsTenantScopedAndVersioned(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	ta, err := store.NewTenants(pool).Create(ctx, "ts-a-"+sfx, "TS A")
	if err != nil {
		t.Fatal(err)
	}
	tb, err := store.NewTenants(pool).Create(ctx, "ts-b-"+sfx, "TS B")
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	src, err := testsync.NewSource(pool, priv)
	if err != nil {
		t.Fatal(err)
	}

	if v := version(ctx, t, pool, ta.ID); v != store.InitialTestSetVersion {
		t.Fatalf("fresh tenant version = %d, want %d", v, store.InitialTestSetVersion)
	}

	idA := createTest(ctx, t, pool, ta.ID, "a-web", "https://a.example.com", true)
	if v := version(ctx, t, pool, ta.ID); v != 2 {
		t.Fatalf("version after create = %d, want 2", v)
	}
	createTest(ctx, t, pool, ta.ID, "a-off", "https://a-off.example.com", false)
	idB := createTest(ctx, t, pool, tb.ID, "b-web", "https://b.example.com", true)
	if v := version(ctx, t, pool, ta.ID); v != 3 {
		t.Fatalf("A's version moved with B's write or missed its own: %d, want 3", v)
	}
	if v := version(ctx, t, pool, tb.ID); v != 2 {
		t.Fatalf("B version = %d, want 2", v)
	}

	inTenant(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		_, err := (store.Tests{}).Update(ctx, s, idA, store.TestInput{
			Name: "a-web", Type: "http", Target: "https://a2.example.com", IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: true,
		})
		return err
	})
	if v := version(ctx, t, pool, ta.ID); v != 4 {
		t.Fatalf("version after update = %d, want 4", v)
	}

	// A's bundle: signed, A's tenant, A's ENABLED tests only, epoch = version.
	ver, signed, err := src.Bundle(ctx, ta.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testsync.Verify(signed, pub, 0)
	if err != nil {
		t.Fatalf("A's bundle does not verify: %v", err)
	}
	if b.TenantID != ta.ID || ver != 4 || b.Epoch != 4 {
		t.Fatalf("A's bundle tenant/epoch = %s/%d (version %d), want %s/4", b.TenantID, b.Epoch, ver, ta.ID)
	}
	if len(b.Tests) != 1 || b.Tests[0].ID != idA || b.Tests[0].Target != "https://a2.example.com" {
		t.Fatalf("A's bundle tests = %+v, want only the enabled, updated A test", b.Tests)
	}
	for _, tt := range b.Tests {
		if tt.ID == idB {
			t.Fatal("ISOLATION BREACH: tenant B's test is in tenant A's bundle")
		}
	}

	// B's bundle carries only B's test.
	_, signedB, err := src.Bundle(ctx, tb.ID)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := testsync.Verify(signedB, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bb.TenantID != tb.ID || len(bb.Tests) != 1 || bb.Tests[0].ID != idB {
		t.Fatalf("B's bundle = %+v", bb)
	}

	// Delete bumps, and the next bundle drops the test.
	inTenant(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		return (store.Tests{}).Delete(ctx, s, idA)
	})
	ver, signed, err = src.Bundle(ctx, ta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 5 {
		t.Fatalf("version after delete = %d, want 5", ver)
	}
	if b, err = testsync.Verify(signed, pub, 4); err != nil || len(b.Tests) != 0 {
		t.Fatalf("post-delete bundle = %+v, %v; want verified and empty", b, err)
	}

	// FORCE RLS: a predicate-free read of the version table in tenant A's scope
	// sees exactly A's row, never B's.
	inTenant(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		var n int
		var owner string
		if err := s.Q.QueryRow(ctx, `SELECT count(*), min(tenant_id::text) FROM tenant_test_set_versions`).Scan(&n, &owner); err != nil {
			return err
		}
		if n != 1 || owner != ta.ID {
			t.Fatalf("RLS: tenant A sees %d version rows (owner %s), want exactly its own", n, owner)
		}
		return nil
	})
	// A write naming another tenant is rejected by the policy's WITH CHECK.
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(ta.ID)), pool, func(ctx context.Context, s tenancy.Scope) error {
		_, err := s.Q.Exec(ctx,
			`UPDATE tenant_test_set_versions SET version = 99 WHERE tenant_id = $1`, tb.ID)
		if err != nil {
			return err
		}
		_, err = s.Q.Exec(ctx, `INSERT INTO tenant_test_set_versions (tenant_id, version) VALUES ($1, 99)`, tb.ID)
		return err
	})
	if err == nil {
		t.Fatal("RLS: tenant A wrote a version row for tenant B")
	}
	if v := version(ctx, t, pool, tb.ID); v != 2 {
		t.Fatalf("ISOLATION BREACH: tenant B's version is %d after tenant A's cross-tenant write, want 2", v)
	}
}

// TestHeartbeatRecordsAppliedVersionPerTenant: the per-agent applied version
// is written under the agent's tenant scope; a batch flushed in tenant A's scope
// cannot touch tenant B's agent even when handed its id.
func TestHeartbeatRecordsAppliedVersionPerTenant(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	ta, err := store.NewTenants(pool).Create(ctx, "hbv-a-"+sfx, "HBV A")
	if err != nil {
		t.Fatal(err)
	}
	tb, err := store.NewTenants(pool).Create(ctx, "hbv-b-"+sfx, "HBV B")
	if err != nil {
		t.Fatal(err)
	}
	agentA, agentB := uuid(t), uuid(t)
	register := func(tenant, id string) {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, s tenancy.Scope) error {
			_, err := (store.Agents{}).Register(ctx, s, id, "agent-"+id[:8], "host", "0.1.0",
				crypto.AgentSPIFFEID(tenant, id), []string{"http"})
			return err
		})
	}
	register(ta.ID, agentA)
	register(tb.ID, agentB)

	inTenant(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		return (store.Agents{}).HeartbeatBatchVersions(ctx, s, []string{agentA, agentB}, []uint64{7, 7})
	})
	read := func(tenant, id string) int64 {
		var v *int64
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, s tenancy.Scope) error {
			return s.Q.QueryRow(ctx, `SELECT test_set_version FROM agents WHERE id = $1`, id).Scan(&v)
		})
		if v == nil {
			return 0
		}
		return *v
	}
	if got := read(ta.ID, agentA); got != 7 {
		t.Fatalf("agent A applied version = %d, want 7", got)
	}
	if got := read(tb.ID, agentB); got != 0 {
		t.Fatalf("ISOLATION BREACH: tenant A's heartbeat batch set tenant B's agent version to %d", got)
	}
}

func uuid(t *testing.T) string {
	t.Helper()
	b, err := crypto.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
