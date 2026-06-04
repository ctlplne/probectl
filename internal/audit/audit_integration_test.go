//go:build integration

package audit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
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
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func TestTenantAuditTamperDetection(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// Fresh tenant => a fresh, empty audit chain for a deterministic test.
	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("audit-%d", time.Now().UnixNano()), "Audit")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenancy.ID(tn.ID)

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
		for i, action := range []string{"tenant.create", "org.create", "user.invite"} {
			if _, err := TenantAppend(ctx, s, "alice", action, fmt.Sprintf("target-%d", i), map[string]any{"i": i}); err != nil {
				return err
			}
		}
		return TenantVerify(ctx, s)
	})
	if err != nil {
		t.Fatalf("append + verify (clean): %v", err)
	}

	// Tamper as a superuser, bypassing the append-only RLS policy.
	if _, err := pool.Exec(ctx,
		`UPDATE audit_events SET actor = 'mallory' WHERE tenant_id = $1 AND seq = 2`, tn.ID); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	verr := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, TenantVerify)
	if verr == nil {
		t.Fatal("TenantVerify should detect tampering, but reported a valid chain")
	}
	t.Logf("tamper correctly detected: %v", verr)
}

func TestProviderAuditTamperDetection(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// The provider stream is global; reset it for a deterministic chain.
	if _, err := pool.Exec(ctx, `TRUNCATE provider_audit_events`); err != nil {
		t.Fatalf("reset provider stream: %v", err)
	}

	for i, action := range []string{"tenant.provision", "breakglass.grant"} {
		if _, err := ProviderAppend(ctx, pool, "operator-x", action, fmt.Sprintf("p-%d", i), map[string]any{"n": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := ProviderVerify(ctx, pool); err != nil {
		t.Fatalf("verify (clean): %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE provider_audit_events SET action = 'hacked' WHERE seq = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := ProviderVerify(ctx, pool); err == nil {
		t.Fatal("ProviderVerify should detect tampering, but reported a valid chain")
	}
}
