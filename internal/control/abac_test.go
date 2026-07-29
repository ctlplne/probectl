// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// TestABACCacheNotPoisonedOnLoadError: CODE-002. A transient scope-setup/query
// fault must NOT be cached as "no policies" (an empty policy set silently widens
// access for the TTL). With a closed pool every load fails; a cold caller must
// receive that failure, the cache must NOT gain an entry, and a prior known-good
// entry must remain available as a stale fallback.
func TestABACCacheNotPoisonedOnLoadError(t *testing.T) {
	c := newClosedABACCache(t)
	c.ttl = time.Hour // long TTL — a poisoned entry would persist

	pols, err := c.policies(context.Background(), "t-acme")
	if err == nil {
		t.Fatal("cold ABAC policy load failure was hidden as an empty policy set")
	}
	if pols != nil {
		t.Fatalf("policies on a failed cold load should be nil, got %d", len(pols))
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
	got, err := c.policies(context.Background(), "t-acme")
	if err != nil {
		t.Fatalf("stale known-good policy fallback returned an error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "p1" {
		t.Fatalf("on load failure the prior entry must be served, got %#v", got)
	}
}
