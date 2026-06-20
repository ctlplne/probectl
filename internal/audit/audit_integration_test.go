// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
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

// TestAppendConcurrencySafe is the regression test for the read-head→insert
// race: before the per-chain advisory locks, two concurrent appends on the
// same chain could both read head seq N and both insert N+1 — UNIQUE
// (tenant_id, seq) then failed one of them with 23505, which surfaced as a
// 500 on whatever API write was being audited (first seen as TestAgentsAPI
// flaking in CI, where parallel test packages share this database).
func TestAppendConcurrencySafe(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// Per-tenant chain: a fresh tenant, hammered from N goroutines.
	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("audit-race-%d", time.Now().UnixNano()), "AuditRace")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenancy.ID(tn.ID)

	const n = 12
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
				_, err := TenantAppend(ctx, s, "racer", "race.append", fmt.Sprintf("t-%d", i), map[string]any{"i": i})
				return err
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent TenantAppend %d: %v", i, err)
		}
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, TenantVerify); err != nil {
		t.Fatalf("chain verify after concurrent appends: %v", err)
	}
	var head int64
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq),0) FROM audit_events WHERE tenant_id = $1`, tn.ID).Scan(&head); err != nil {
		t.Fatalf("head: %v", err)
	}
	if head != n {
		t.Fatalf("head seq = %d, want %d (lost or duplicated appends)", head, n)
	}

	// Provider chain: same race, global stream. Anchor on the current head and
	// verify only the suffix (the database is shared across test packages).
	phead, err := ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatalf("provider head: %v", err)
	}
	perrs := make([]error, n)
	var pwg sync.WaitGroup
	for i := 0; i < n; i++ {
		pwg.Add(1)
		go func(i int) {
			defer pwg.Done()
			_, perrs[i] = ProviderAppend(ctx, pool, "racer", "race.provider", fmt.Sprintf("p-%d", i), map[string]any{"i": i})
		}(i)
	}
	pwg.Wait()
	for i, err := range perrs {
		if err != nil {
			t.Fatalf("concurrent ProviderAppend %d: %v", i, err)
		}
	}
	if err := ProviderVerifyFrom(ctx, pool, phead); err != nil {
		t.Fatalf("provider chain verify after concurrent appends: %v", err)
	}
}

func TestProviderAuditTamperDetection(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// The provider stream is GLOBAL and the integration database is shared
	// across test packages running in parallel — so this test never truncates
	// and never asserts the whole chain. It anchors on the current head,
	// verifies only its own suffix, tampers only its own record, and RESTORES
	// it (a corrupted chain left behind would fail other packages' verifies).
	head, err := ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	for i, action := range []string{"tenant.provision", "breakglass.grant"} {
		if _, err := ProviderAppend(ctx, pool, "operator-x", action, fmt.Sprintf("p-%d", i), map[string]any{"n": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := ProviderVerifyFrom(ctx, pool, head); err != nil {
		t.Fatalf("verify (clean): %v", err)
	}

	// Tamper with OUR second record, bypassing append-only (superuser).
	victim := head + 2
	var orig string
	if err := pool.QueryRow(ctx,
		`UPDATE provider_audit_events SET action = 'hacked' WHERE seq = $1 RETURNING 'breakglass.grant'`,
		victim).Scan(&orig); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := ProviderVerifyFrom(ctx, pool, head); err == nil {
		t.Fatal("ProviderVerifyFrom should detect tampering, but reported a valid chain")
	}

	// Restore, leaving the shared chain valid for everyone else.
	if _, err := pool.Exec(ctx,
		`UPDATE provider_audit_events SET action = $2 WHERE seq = $1`, victim, orig); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := ProviderVerifyFrom(ctx, pool, head); err != nil {
		t.Fatalf("verify (restored): %v", err)
	}
}

func TestTenantSubjectErasureProjectsAuditList(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("audit-privacy-%d", time.Now().UnixNano()), "AuditPrivacy")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenancy.ID(tn.ID)
	subject := "alice@example.com"

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
		if _, err := TenantAppend(ctx, s, subject, "directory.provision", subject, map[string]any{
			"user_name": subject,
			"group":     "admins",
		}); err != nil {
			return err
		}
		if _, err := RecordSubjectErasure(ctx, s, "privacy-admin", subject, "data subject request"); err != nil {
			return err
		}
		if err := TenantVerify(ctx, s); err != nil {
			return err
		}
		events, err := List(ctx, s, 0, 10)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(events)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(raw)), subject) {
			return fmt.Errorf("projected audit list leaked erased subject: %s", raw)
		}
		if events[0].Hash == "" || events[0].PrevHash != genesis {
			return fmt.Errorf("chain fields were not preserved in projection: %#v", events[0])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("subject erasure projection: %v", err)
	}
}
