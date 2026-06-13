// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// TestABACCacheNotPoisonedOnLoadError: CODE-002. A transient scope-setup/query
// fault must NOT be cached as "no policies" (an empty policy set silently widens
// access for the TTL). With a dead pool every load fails; the cache must NOT
// gain an entry, and a later (recovered) call must still attempt a load — i.e.
// the empty result is never persisted.
func TestABACCacheNotPoisonedOnLoadError(t *testing.T) {
	// A pool that can be created but never connects (Acquire fails on use).
	cfg, err := pgxpool.ParseConfig("postgres://probectl@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	c := newABACCache(pool)
	c.ttl = time.Hour // long TTL — a poisoned entry would persist

	pols := c.policies(context.Background(), "t-acme")
	if pols != nil {
		t.Fatalf("policies on a failed load should be nil, got %d", len(pols))
	}

	// The key invariant: the failed load left NO cache entry (not even an empty
	// one), so the cache was not poisoned.
	c.mu.Lock()
	_, cached := c.data["t-acme"]
	c.mu.Unlock()
	if cached {
		t.Fatal("CODE-002: a failed ABAC load must NOT cache an empty policy set (cache poisoned)")
	}

	// A prior good entry is served (stale-but-correct) rather than dropped when a
	// later load fails.
	good := []auth.Policy{{ID: "p1"}}
	c.mu.Lock()
	c.data["t-acme"] = abacEntry{policies: good, expiry: time.Now().Add(-time.Minute)} // expired
	c.mu.Unlock()
	got := c.policies(context.Background(), "t-acme")
	if len(got) != 1 || got[0].ID != "p1" {
		t.Fatalf("on load failure the prior entry must be served, got %#v", got)
	}
}
