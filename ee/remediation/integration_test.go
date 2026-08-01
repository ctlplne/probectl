// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package remediation

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// The S-EE5 integration leg (live Postgres): proposals round-trip through
// remediation_proposals under tenant RLS, a tenant sees ONLY its own proposals
// (cross-tenant isolation), Decide is optimistic (only a proposed row moves),
// and the full Service writes the propose→approve trail to the tamper-evident
// tenant audit stream.

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
	svc := New(NewPGStore(pool), est, NewTenantAudit(pool), Config{ApprovalsEnabled: true, MaxBlastRadius: 50})

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

type failingScopedAudit struct{ err error }

func (f failingScopedAudit) Append(context.Context, string, string, string, string, map[string]any) error {
	return f.err
}

func (f failingScopedAudit) appendScoped(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
	return f.err
}

func TestRemediationMutationAndAuditAreAtomicPG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	tnA := itTenant(t, pool, "it-rem-atomic-a-"+suffix)
	tnB := itTenant(t, pool, "it-rem-atomic-b-"+suffix)
	store := NewPGStore(pool)
	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 3}}
	good := New(store, est, NewTenantAudit(pool), Config{ApprovalsEnabled: true, MaxBlastRadius: 50})

	pA, err := good.Propose(ctx, tnA, "ai:propose_remediation", rem.ProposeInput{
		Kind: rem.KindOpenTicket, Title: "tenant A baseline",
	})
	if err != nil {
		t.Fatalf("seed tenant A: %v", err)
	}
	pB, err := good.Propose(ctx, tnB, "ai:propose_remediation", rem.ProposeInput{
		Kind: rem.KindOpenTicket, Title: "tenant B baseline",
	})
	if err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	auditFailure := errors.New("injected scoped audit failure")
	failing := New(store, est, failingScopedAudit{err: auditFailure}, Config{ApprovalsEnabled: true, MaxBlastRadius: 50})
	if _, err := failing.Approve(ctx, tnA, "user:admin@example.com", pA.ID, "go"); !errors.Is(err, auditFailure) {
		t.Fatalf("approve with failed audit = %v, want %v", err, auditFailure)
	}
	if _, err := failing.Propose(ctx, tnA, "user:a@example.com", rem.ProposeInput{
		Kind: rem.KindOpenTicket, Title: "must roll back",
	}); !errors.Is(err, auditFailure) {
		t.Fatalf("propose with failed audit = %v, want %v", err, auditFailure)
	}

	gotA, err := store.Get(ctx, tnA, pA.ID)
	if err != nil {
		t.Fatalf("get tenant A: %v", err)
	}
	if gotA.State != rem.StateProposed {
		t.Fatalf("failed audit published tenant A decision: %+v", gotA)
	}
	listA, err := store.List(ctx, tnA)
	if err != nil {
		t.Fatalf("list tenant A: %v", err)
	}
	if len(listA) != 1 {
		t.Fatalf("failed audit published tenant A proposal: got %d rows, want 1", len(listA))
	}
	gotB, err := store.Get(ctx, tnB, pB.ID)
	if err != nil {
		t.Fatalf("get tenant B: %v", err)
	}
	if gotB.State != rem.StateProposed {
		t.Fatalf("tenant A audit failure changed tenant B: %+v", gotB)
	}
}
