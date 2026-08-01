// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

//go:build integration

package provider

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
)

// breakGlassRacePair provisions one operator+tenant and returns a store bound
// to the real pool, for driving decision races against PostgreSQL.
func breakGlassRacePair(t *testing.T) (*PGStore, *pgxpool.Pool, Operator, Tenant, time.Time) {
	t.Helper()
	pool := pgPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	store := NewPGStore(pool)
	now := time.Now().UTC()
	stamp := now.UnixNano()

	operator, err := store.CreateOperator(ctx, Operator{
		Email: fmt.Sprintf("bg-decision-%d@msp.example", stamp),
		Name:  "Break-glass Decision Race",
		Role:  RoleOperator,
	}, crypto.Hash([]byte(fmt.Sprintf("bg-decision-%d", stamp))))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := store.CreateTenant(ctx, fmt.Sprintf("bg-decision-%d", stamp),
		"Break-glass Decision Tenant", "pooled", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return store, pool, operator, tenant, now
}

func newPendingGrant(t *testing.T, store *PGStore, op Operator, tn Tenant, now time.Time) Grant {
	t.Helper()
	g, err := store.CreateGrant(context.Background(), Grant{
		OperatorID: op.ID,
		TenantID:   tn.ID,
		Reason:     "decision-race regression",
		Scope:      "read",
		GrantedBy:  op.Email,
		GrantedAt:  now.Add(-time.Minute),
		ExpiresAt:  now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestBreakGlassConsentDenyRaceHasExactlyOneWinner drives consent and deny
// concurrently at the SAME pending grant (Foundation-Loop S-ae06d833). They
// are mutually exclusive decisions on the tenant's side. Before this, consent
// read state from a non-locking fetch OUTSIDE the mutation and issued an
// unguarded UPDATE, so both could "succeed" and the last writer won. Now each
// transition takes the row lock and re-states its precondition as UPDATE
// predicates, so exactly one commits and the loser fails closed.
//
// Revoke is deliberately NOT in this race: revoking an already-consented grant
// is the legitimate operator action, so consent+revoke both committing is
// correct. TestBreakGlassRevokeAlwaysWinsAccess covers that ordering.
func TestBreakGlassConsentDenyRaceHasExactlyOneWinner(t *testing.T) {
	store, _, op, tn, now := breakGlassRacePair(t)
	ctx := context.Background()

	for attempt := 0; attempt < 8; attempt++ {
		g := newPendingGrant(t, store, op, tn, now)

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			winners []string
		)
		record := func(name string, err error) {
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners = append(winners, name)
				return
			}
			// A loss is fail-closed either way: the re-predicated UPDATE
			// matched no row (ErrGrantDecided) or the partial unique index
			// refused a second active grant (ErrConflict).
			if !errors.Is(err, ErrGrantDecided) && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
				t.Errorf("%s lost the race with an unexpected error: %v", name, err)
			}
		}
		start := make(chan struct{})
		for name, decide := range map[string]func() error{
			"consent": func() error { _, err := store.ConsentGrant(ctx, g.ID, "admin@t", now); return err },
			"deny":    func() error { _, err := store.DenyGrant(ctx, g.ID, "admin@t", now); return err },
		} {
			wg.Add(1)
			go func(name string, decide func() error) {
				defer wg.Done()
				<-start
				record(name, decide())
			}(name, decide)
		}
		close(start)
		wg.Wait()

		if len(winners) != 1 {
			t.Fatalf("attempt %d: %d decisions committed (%v); consent and deny are mutually exclusive",
				attempt, len(winners), winners)
		}
		final, err := store.GetGrant(ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		if final.ConsentedAt != nil && final.DeniedAt != nil {
			t.Fatalf("attempt %d: grant is BOTH consented and denied", attempt)
		}
		// Release the grant so the next attempt starts from a clean state —
		// migration 0087 permits only one ACTIVE grant per (operator, tenant),
		// which is exactly what TestBreakGlassConcurrentConsentsYieldOneActiveGrant
		// asserts.
		if final.ConsentedAt != nil {
			if _, err := store.RevokeGrant(ctx, g.ID, op.Email, now); err != nil {
				t.Fatalf("attempt %d: releasing the consented grant: %v", attempt, err)
			}
		}
	}
}

// TestBreakGlassRevokeAlwaysWinsAccess: revoke may legitimately race a consent
// on the same grant, and BOTH may commit — but whatever the interleaving, a
// revoked grant must never be usable. Access is decided by storage state, not
// by which goroutine got there first.
func TestBreakGlassRevokeAlwaysWinsAccess(t *testing.T) {
	store, _, op, tn, now := breakGlassRacePair(t)
	ctx := context.Background()

	for attempt := 0; attempt < 8; attempt++ {
		g := newPendingGrant(t, store, op, tn, now)
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _, _ = store.ConsentGrant(ctx, g.ID, "admin@t", now) }()
		go func() { defer wg.Done(); <-start; _, _ = store.RevokeGrant(ctx, g.ID, op.Email, now) }()
		close(start)
		wg.Wait()

		final, err := store.GetGrant(ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		if final.RevokedAt != nil && final.Usable(now.Add(time.Second)) {
			t.Fatalf("attempt %d: a revoked grant reports usable", attempt)
		}
		if final.RevokedAt != nil {
			if _, err := store.UseGrant(ctx, g.ID, op.ID, now.Add(time.Second)); err == nil {
				t.Fatalf("attempt %d: a revoked grant was USED", attempt)
			}
			continue
		}
		// Consent won without a revoke: release it so the single-active-grant
		// invariant leaves the next attempt a clean slate.
		if final.ConsentedAt != nil {
			if _, err := store.RevokeGrant(ctx, g.ID, op.Email, now); err != nil {
				t.Fatalf("attempt %d: releasing the consented grant: %v", attempt, err)
			}
		}
	}
}

// TestBreakGlassRevokeAfterConsentIsNotUndone: revoke legitimately follows
// consent, but a consent that loses to a revoke must NOT resurrect access —
// the storage predicates, not the caller, enforce that.
func TestBreakGlassConsentCannotFollowRevoke(t *testing.T) {
	store, _, op, tn, now := breakGlassRacePair(t)
	ctx := context.Background()
	g := newPendingGrant(t, store, op, tn, now)

	if _, err := store.RevokeGrant(ctx, g.ID, op.Email, now); err != nil {
		t.Fatalf("revoke a pending grant: %v", err)
	}
	if _, err := store.ConsentGrant(ctx, g.ID, "admin@t", now.Add(time.Second)); !errors.Is(err, ErrGrantDecided) {
		t.Fatalf("consent after revoke = %v, want ErrGrantDecided (it must never resurrect access)", err)
	}
	final, err := store.GetGrant(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.ConsentedAt != nil {
		t.Fatal("a revoked grant was consented afterwards — access was resurrected")
	}
	if final.Usable(now.Add(2 * time.Second)) {
		t.Fatal("a revoked grant reports usable")
	}
}

// TestBreakGlassConcurrentConsentsYieldOneActiveGrant proves the storage-level
// invariant: two grants for the same operator+tenant cannot BOTH be active,
// because migration 0087's partial unique index makes that unrepresentable.
func TestBreakGlassConcurrentConsentsYieldOneActiveGrant(t *testing.T) {
	store, _, op, tn, now := breakGlassRacePair(t)
	ctx := context.Background()

	first := newPendingGrant(t, store, op, tn, now)
	second := newPendingGrant(t, store, op, tn, now)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
	)
	start := make(chan struct{})
	for _, g := range []Grant{first, second} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			if _, err := store.ConsentGrant(ctx, id, "admin@t", now); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}(g.ID)
	}
	close(start)
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("%d concurrent consents committed for the same (operator, tenant); storage must permit exactly one active grant", accepted)
	}
}
