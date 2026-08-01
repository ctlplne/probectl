// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

// waitForABACLoad blocks until the shared fill has begun.
func waitForABACLoad(t *testing.T, loads *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if loads.Load() >= 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the shared fill never started within 2s")
}

// newTestABACCache builds a cache whose loads are driven by the test.
func newTestABACCache(load func(context.Context, string) ([]auth.Policy, error)) *abacCache {
	return &abacCache{
		ttl:         30 * time.Second,
		data:        map[string]abacEntry{},
		generations: map[string]uint64{},
		load:        load,
	}
}

// Concurrent misses for one tenant must share ONE store read. Before this, each
// in-flight request opened its own tenant-scoped transaction on a cold cache,
// so a restart under load turned every request into a query.
func TestABACCacheCollapsesConcurrentMisses(t *testing.T) {
	var loads atomic.Int64
	release := make(chan struct{})
	c := newTestABACCache(func(context.Context, string) ([]auth.Policy, error) {
		loads.Add(1)
		<-release // hold the leader open so the others must join it
		return []auth.Policy{{Effect: auth.PolicyDeny}}, nil
	})

	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	got := make([][]auth.Policy, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = c.policies(context.Background(), "tenant-a")
		}()
	}
	// Let every caller reach the fill before the loader returns.
	waitForABACLoad(t, &loads)
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := loads.Load(); n != 1 {
		t.Fatalf("%d callers caused %d store reads, want exactly 1 — the fill is not shared", callers, n)
	}
	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if len(got[i]) != 1 || got[i][0].Effect != auth.PolicyDeny {
			t.Fatalf("caller %d got %v, want the shared deny policy", i, got[i])
		}
	}
}

// The generation guard is the half singleflight cannot express: dedup does not
// know when its result went stale. A policy change committed while a load is in
// flight must never be overwritten by the older snapshot.
func TestABACCacheDiscardsSnapshotInvalidatedDuringLoad(t *testing.T) {
	var c *abacCache
	var loads atomic.Int64
	invalidated := make(chan struct{})
	c = newTestABACCache(func(context.Context, string) ([]auth.Policy, error) {
		if loads.Add(1) == 1 {
			// A committed mutation lands while this read is in flight.
			c.invalidate("tenant-a")
			close(invalidated)
			return []auth.Policy{{Effect: auth.PolicyAllow}}, nil // the stale snapshot
		}
		return []auth.Policy{{Effect: auth.PolicyDeny}}, nil // the post-change truth
	})

	pols, err := c.policies(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	<-invalidated
	if len(pols) != 1 || pols[0].Effect != auth.PolicyDeny {
		t.Fatalf("got %v, want the reloaded post-invalidation policy: a snapshot read before a "+
			"committed change must not publish, or a revoked allow survives its own revocation", pols)
	}
	if n := loads.Load(); n != 2 {
		t.Fatalf("loads = %d, want 2 (the discarded snapshot then the reload)", n)
	}
}

// Persistent churn must fail closed rather than spin: authorization refuses.
func TestABACCacheFailsClosedUnderRelentlessInvalidation(t *testing.T) {
	var c *abacCache
	c = newTestABACCache(func(context.Context, string) ([]auth.Policy, error) {
		c.invalidate("tenant-a") // every load is invalidated before it can publish
		return []auth.Policy{{Effect: auth.PolicyAllow}}, nil
	})
	if _, err := c.policies(context.Background(), "tenant-a"); !errors.Is(err, errABACInvalidatedDuringLoad) {
		t.Fatalf("error = %v, want %v — bounded attempts must refuse, not spin", err, errABACInvalidatedDuringLoad)
	}
}

// The shared fill is detached from the leader's request context: one client
// hanging up must not fail every waiter closed.
func TestABACCacheFillSurvivesLeaderCancellation(t *testing.T) {
	started := make(chan struct{})
	c := newTestABACCache(func(ctx context.Context, _ string) ([]auth.Policy, error) {
		close(started)
		time.Sleep(30 * time.Millisecond)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []auth.Policy{{Effect: auth.PolicyDeny}}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	var pols []auth.Policy
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		pols, err = c.policies(ctx, "tenant-a")
	}()
	<-started
	cancel() // the leader's client hangs up mid-load
	<-done

	if err != nil {
		t.Fatalf("a canceled leader must not fail the shared fill: %v", err)
	}
	if len(pols) != 1 {
		t.Fatalf("got %v, want the loaded policy", pols)
	}
}
