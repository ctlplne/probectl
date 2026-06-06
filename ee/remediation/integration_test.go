//go:build integration

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package remediation

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	rem "github.com/imfeelingtheagi/probectl/internal/remediation"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// The S-EE5 integration leg (live Postgres): proposals round-trip through
// remediation_proposals under tenant RLS, a tenant sees ONLY its own proposals
// (cross-tenant isolation), Decide is optimistic (only a proposed row moves),
// and the full Service writes the propose→approve trail to the tamper-evident
// tenant audit stream.

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

func itTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (slug, name) VALUES ($1, $1)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func auditFn(pool *pgxpool.Pool) Audit {
	return func(ctx context.Context, tenantID, actor, action, target string, data map[string]any) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := audit.TenantAppend(ctx, sc, actor, action, target, data)
			return err
		})
	}
}

func TestRemediationStoreRoundTripPG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	tnA := itTenant(t, pool, "it-rem-a")
	tnB := itTenant(t, pool, "it-rem-b")
	store := NewPGStore(pool)

	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	in := rem.Proposal{
		TenantID: tnA, Kind: rem.KindRerouteSuggestion, Title: "reroute around hop",
		Rationale: "incident", Target: "hop:10.0.0.1",
		DryRun: rem.DryRun{BlastRadius: 4, ImpactedServices: []string{"svc-1"}},
		State:  rem.StateProposed, ProposedBy: "ai:propose_remediation", CreatedAt: now,
	}
	saved, err := store.Insert(ctx, tnA, in)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if saved.ID == "" || saved.State != rem.StateProposed {
		t.Fatalf("insert returned %+v", saved)
	}

	got, err := store.Get(ctx, tnA, saved.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DryRun.BlastRadius != 4 || len(got.DryRun.ImpactedServices) != 1 {
		t.Fatalf("dry-run did not round-trip: %+v", got.DryRun)
	}

	// Cross-tenant isolation: tenant B cannot see tenant A's proposal.
	if _, err := store.Get(ctx, tnB, saved.ID); err == nil {
		t.Fatal("CROSS-TENANT LEAK: tenant B read tenant A's proposal")
	}
	list, err := store.List(ctx, tnB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("tenant B sees %d proposals, want 0", len(list))
	}

	// Decide moves proposed → approved exactly once (optimistic).
	dec, err := store.Decide(ctx, tnA, saved.ID, rem.StateApproved, "user:admin", "ok", now)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.State != rem.StateApproved || dec.DecidedBy != "user:admin" || dec.DecidedAt == nil {
		t.Fatalf("decide result: %+v", dec)
	}
	// A second decide on the now-approved row fails (not proposed).
	if _, err := store.Decide(ctx, tnA, saved.ID, rem.StateRejected, "user:admin", "", now); err != rem.ErrNotProposed {
		t.Fatalf("second decide: err=%v, want ErrNotProposed", err)
	}
}

func TestRemediationServiceAuditTrailPG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	tn := itTenant(t, pool, "it-rem-audit")

	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 3}}
	svc := New(NewPGStore(pool), est, auditFn(pool), Config{ApprovalsEnabled: true, MaxBlastRadius: 50})

	p, err := svc.Propose(ctx, tn, "ai:propose_remediation", rem.ProposeInput{
		Kind: rem.KindRerouteSuggestion, Title: "reroute", Target: "hop:10.0.0.2",
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := svc.Approve(ctx, tn, "user:admin@example.com", p.ID, "go"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// The propose + approve actions are in the tenant's tamper-evident stream,
	// and the chain verifies.
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		events, err := audit.List(ctx, sc, 0, 100)
		if err != nil {
			return err
		}
		var sawPropose, sawApprove bool
		for _, e := range events {
			switch e.Action {
			case "remediation.propose":
				sawPropose = true
			case "remediation.approve":
				sawApprove = true
			}
		}
		if !sawPropose || !sawApprove {
			t.Fatalf("audit trail missing entries: propose=%v approve=%v", sawPropose, sawApprove)
		}
		return audit.TenantVerify(ctx, sc)
	})
	if err != nil {
		t.Fatalf("audit verify: %v", err)
	}
}
