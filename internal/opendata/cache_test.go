// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// newCappedCache returns a cache with a fixed clock, a long TTL (so nothing
// expires during the test), and the requested hard cap.
func newCappedCache(capacity int, now time.Time) *cache {
	c := newCache(time.Hour)
	c.now = func() time.Time { return now }
	c.setMax(capacity)
	return c
}

// TestCachePutAtCapacityIsConstantScan is the GAP-06 regression guard. Once the
// shared enrichment cache is full, inserting a new key must examine a constant
// number of entries to make room — not ~len(m). The old implementation ran two
// full O(n) map scans per capacity insert (evictExpiredLocked + evictOldestLocked)
// while holding the global lock that every reader also needs, so one tenant's
// distinct-IP churn degraded deployment-wide enrichment (docs/guardrails.md
// G7-10). This asserts the hot path is O(1): the scan work for a single
// capacity insert does not grow with the number of cached entries.
func TestCachePutAtCapacityIsConstantScan(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	// scansForOneOverflowPut fills the cache to exactly `capacity` distinct
	// keys, then measures how many entries a single new-key insert examines.
	scansForOneOverflowPut := func(capacity int) uint64 {
		c := newCappedCache(capacity, base)
		for i := 0; i < capacity; i++ {
			key := fmt.Sprintf("fill-%d", i)
			c.put(key, Enrichment{IP: key})
		}
		if got := c.stats().Entries; got != capacity {
			t.Fatalf("precondition: cache has %d entries, want it full at %d", got, capacity)
		}
		c.mu.Lock()
		c.scans = 0 // measure only the single overflow insert below
		c.mu.Unlock()

		c.put("overflow-key", Enrichment{IP: "overflow-key"})

		c.mu.Lock()
		defer c.mu.Unlock()
		if got := len(c.m); got != capacity {
			t.Fatalf("cap=%d: after overflow insert cache holds %d entries, want it still at the cap %d",
				capacity, got, capacity)
		}
		return c.scans
	}

	small := scansForOneOverflowPut(1024)
	large := scansForOneOverflowPut(8192)

	// O(1): the same single capacity insert must cost the same regardless of
	// how many entries are cached. A full-scan eviction would scan ~len, so
	// `large` would be ~8x `small`.
	if small != large {
		t.Fatalf("put-at-capacity is not O(1): a single capacity insert scanned %d entries at cap=1024 "+
			"but %d at cap=8192 (scan work grows with len — the O(n) full-scan regression)", small, large)
	}
	// And it must be a small constant, not ~len. cap=1024 alone is enough to
	// separate O(1) (a handful) from O(n) (~1024+ per insert).
	const o1Ceiling = 8
	if small > o1Ceiling {
		t.Fatalf("put-at-capacity scanned %d entries for one insert into a 1024-entry cache; want O(1) (<=%d). "+
			"An O(n) full-map-scan eviction scans ~len entries per capacity insert.", small, o1Ceiling)
	}
}

// TestCacheGetReturnsFreshValue proves a put is readable and returns the stored
// enrichment unchanged.
func TestCacheGetReturnsFreshValue(t *testing.T) {
	c := newCache(time.Hour)
	want := Enrichment{IP: "198.51.100.7", CountryCode: "US", ASName: "EXAMPLE-AS"}
	c.put("198.51.100.7", want)

	got, ok := c.get("198.51.100.7")
	if !ok {
		t.Fatal("get missed a key that was just put")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("get returned %+v, want the freshly stored %+v", got, want)
	}
}

// TestCacheExpiredEntryNotReturned proves an entry past its TTL is a miss (and
// is counted as expired), never served stale.
func TestCacheExpiredEntryNotReturned(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newCache(time.Minute)
	c.now = func() time.Time { return now }
	c.put("203.0.113.9", Enrichment{IP: "203.0.113.9", CountryCode: "ZZ"})

	if _, ok := c.get("203.0.113.9"); !ok {
		t.Fatal("entry should be a hit before its TTL elapses")
	}

	now = now.Add(2 * time.Minute) // past the 1-minute TTL
	if _, ok := c.get("203.0.113.9"); ok {
		t.Fatal("expired entry must not be returned")
	}
	if st := c.stats(); st.Expired == 0 {
		t.Fatalf("expired lookup should be counted: %+v", st)
	}
}

// TestCacheEvictsLeastRecentlyUsed proves overflow eviction removes the
// least-recently-used entry specifically — not an arbitrary/random one. A get
// counts as a use and must protect its entry from the next eviction.
func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newCache(time.Hour)
	c.now = func() time.Time { return now }
	c.setMax(3)

	c.put("a", Enrichment{IP: "a"})
	c.put("b", Enrichment{IP: "b"})
	c.put("c", Enrichment{IP: "c"}) // order, LRU..MRU: a, b, c

	// Touch "a" so it becomes most-recently-used; now "b" is the LRU.
	if _, ok := c.get("a"); !ok {
		t.Fatal("precondition: a should be present")
	}

	// Insert a 4th key at capacity: the LRU ("b") must be the one evicted.
	c.put("d", Enrichment{IP: "d"})

	if _, ok := c.get("b"); ok {
		t.Fatal("least-recently-used entry b should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.get(k); !ok {
			t.Fatalf("entry %q should still be cached (only the LRU should be evicted)", k)
		}
	}
	if st := c.stats(); st.Entries != 3 || st.Evictions == 0 {
		t.Fatalf("expected exactly the cap worth of entries with a recorded eviction, got %+v", st)
	}
}
