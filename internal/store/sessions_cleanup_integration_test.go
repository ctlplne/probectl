// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func sessionCleanupIdentity(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	label string,
) (tenantID, userID string) {
	t.Helper()
	suffix := fmt.Sprintf("%s-%d", label, time.Now().UnixNano())
	tenant, err := NewTenants(pool).Create(ctx, suffix, "Session cleanup "+label)
	if err != nil {
		t.Fatalf("create %s tenant: %v", label, err)
	}
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (Users{}).Create(ctx, sc, suffix+"@example.com", "Cleanup "+label)
		if err == nil {
			userID = user.ID
		}
		return err
	})
	return tenant.ID, userID
}

func TestSessionDetailCleanupTenantIsolationAndCallbackRace(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tenantA, userA := sessionCleanupIdentity(ctx, t, pool, "tenant-a")
	tenantB, userB := sessionCleanupIdentity(ctx, t, pool, "tenant-b")
	sessions := NewSessions(pool)
	horizon := time.Hour
	now := time.Now()

	type fixture struct {
		hash     []byte
		tenantID string
		userID   string
		expires  time.Time
	}
	create := func(name string, f fixture) {
		t.Helper()
		if err := sessions.Create(ctx, f.hash, auth.Session{
			TenantID: f.tenantID, UserID: f.userID,
			Email: name + "@example.com", DisplayName: "PII " + name,
			ExpiresAt: f.expires,
		}); err != nil {
			t.Fatalf("create %s session: %v", name, err)
		}
	}

	expiredA := crypto.Hash([]byte("cleanup-expired-a-" + tenantA))
	liveA := crypto.Hash([]byte("cleanup-live-a-" + tenantA))
	recentReplacedA := crypto.Hash([]byte("cleanup-recent-replaced-a-" + tenantA))
	agedReplacedA := crypto.Hash([]byte("cleanup-aged-replaced-a-" + tenantA))
	expiredB := crypto.Hash([]byte("cleanup-expired-b-" + tenantB))
	create("expired-a", fixture{expiredA, tenantA, userA, now.Add(-time.Minute)})
	create("live-a", fixture{liveA, tenantA, userA, now.Add(4 * horizon)})
	create("recent-replaced-a", fixture{recentReplacedA, tenantA, userA, now.Add(4 * horizon)})
	create("aged-replaced-a", fixture{agedReplacedA, tenantA, userA, now.Add(4 * horizon)})
	create("expired-b", fixture{expiredB, tenantB, userB, now.Add(-time.Minute)})

	markReplaced := func(hash []byte, at time.Time) {
		t.Helper()
		inTenant(ctx, t, pool, tenantA, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx,
				`UPDATE sessions SET replaced_at = $2
				  WHERE tenant_id = $1 AND token_hash = $3`,
				tenantA, at, hash,
			); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx,
				`UPDATE credential_locators SET replaced_at = $2
				  WHERE tenant_id = $1
				    AND credential_kind = 'session'
				    AND token_hash = $3`,
				tenantA, at, hash,
			)
			return err
		})
	}
	markReplaced(recentReplacedA, now.Add(-horizon/2))
	markReplaced(agedReplacedA, now.Add(-2*horizon))

	deleted, err := sessions.PruneInactive(ctx, tenantA, horizon)
	if err != nil {
		t.Fatalf("prune tenant A session details: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("pruned tenant A details = %d, want expired + aged replacement", deleted)
	}

	assertDetailCount := func(tenantID string, hashes [][]byte, want int) {
		t.Helper()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			var got int
			if err := sc.Q.QueryRow(ctx,
				`SELECT count(*) FROM sessions
				  WHERE tenant_id = $1 AND token_hash = ANY($2::bytea[])`,
				tenantID, hashes,
			).Scan(&got); err != nil {
				return err
			}
			if got != want {
				t.Fatalf("tenant %s detail rows = %d, want %d", tenantID, got, want)
			}
			return nil
		})
	}
	assertDetailCount(tenantA, [][]byte{expiredA, liveA, recentReplacedA, agedReplacedA}, 2)
	// The tenant-A operation cannot erase even an already-expired tenant-B row.
	assertDetailCount(tenantB, [][]byte{expiredB}, 1)

	// Cleanup removes identity detail, not the hash-only global lock. Even after
	// the detail row is gone, retries of a consumed callback remain losers.
	var retainedLocators int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM credential_locators
		  WHERE tenant_id = $1
		    AND credential_kind = 'session'
		    AND token_hash = ANY($2::bytea[])`,
		tenantA, [][]byte{expiredA, agedReplacedA},
	).Scan(&retainedLocators); err != nil {
		t.Fatalf("count retained locator tombstones: %v", err)
	}
	if retainedLocators != 2 {
		t.Fatalf("retained locator tombstones = %d, want 2", retainedLocators)
	}
	var retryWG sync.WaitGroup
	retryResults := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		i := i
		retryWG.Add(1)
		go func() {
			defer retryWG.Done()
			created, err := sessions.ReplaceAuthenticatedByHash(
				ctx, agedReplacedA, nil,
				crypto.Hash([]byte(fmt.Sprintf("aged-retry-%d-%s", i, tenantA))),
				auth.Session{
					TenantID: tenantA, UserID: userA,
					ExpiresAt: time.Now().Add(horizon),
				},
			)
			if err != nil {
				t.Errorf("retry consumed callback %d: %v", i, err)
			}
			retryResults <- created
		}()
	}
	retryWG.Wait()
	close(retryResults)
	for created := range retryResults {
		if created {
			t.Fatal("cleanup reopened an already-consumed callback predecessor")
		}
	}

	// Race the cleaner with two fresh-authentication callbacks from an expired
	// predecessor. Deleting the PII row must not delete their shared locator
	// lock: exactly one callback may commit a successor.
	raceOld := crypto.Hash([]byte("cleanup-race-old-" + tenantA))
	create("race-old", fixture{raceOld, tenantA, userA, now.Add(-time.Minute)})
	raceNext := [][]byte{
		crypto.Hash([]byte("cleanup-race-next-a-" + tenantA)),
		crypto.Hash([]byte("cleanup-race-next-b-" + tenantA)),
	}
	start := make(chan struct{})
	type replacementResult struct {
		created bool
		err     error
	}
	replacements := make(chan replacementResult, 2)
	cleanupResult := make(chan error, 1)
	var raceWG sync.WaitGroup
	raceWG.Add(3)
	go func() {
		defer raceWG.Done()
		<-start
		_, err := sessions.PruneInactive(ctx, tenantA, horizon)
		cleanupResult <- err
	}()
	for _, nextHash := range raceNext {
		nextHash := nextHash
		go func() {
			defer raceWG.Done()
			<-start
			created, err := sessions.ReplaceAuthenticatedByHash(
				ctx, raceOld, nil, nextHash,
				auth.Session{
					TenantID: tenantA, UserID: userA,
					ExpiresAt: time.Now().Add(horizon),
				},
			)
			replacements <- replacementResult{created: created, err: err}
		}()
	}
	close(start)
	raceWG.Wait()
	close(replacements)
	if err := <-cleanupResult; err != nil {
		t.Fatalf("concurrent cleanup: %v", err)
	}
	var winners, losers int
	for result := range replacements {
		if result.err != nil {
			t.Fatalf("concurrent authenticated replacement: %v", result.err)
		}
		if result.created {
			winners++
		} else {
			losers++
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("cleanup/callback race winners=%d losers=%d, want 1/1", winners, losers)
	}
	assertDetailCount(tenantA, [][]byte{raceOld}, 0)
	var liveSuccessors int
	for _, nextHash := range raceNext {
		got, err := sessions.LookupByHash(ctx, nextHash, horizon)
		if err != nil {
			t.Fatalf("lookup callback successor: %v", err)
		}
		if got != nil {
			liveSuccessors++
		}
	}
	if liveSuccessors != 1 {
		t.Fatalf("live callback successors = %d, want 1", liveSuccessors)
	}
}
