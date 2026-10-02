// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"strconv"
	"testing"
	"time"
)

// churnKey returns a distinct limiter key for the i-th rotated identity.
func churnKey(i int) string { return "ip:churn:" + strconv.Itoa(i) }

// AUTHZ-13 regression: an attacker rotating through unbounded distinct keys
// must not grow the limiter table past its cap. Pre-fix the table swept the
// whole map (O(n) under the global mutex) but evicted nothing when entries
// were fresh, so len(entries) grew without bound — this asserts the strict
// cap. RED on the pre-fix unbounded map (len climbs to maxEntries+extra),
// GREEN once inserts evict the least-recently-used entry in O(1).
func TestLimiterBoundsTableSize(t *testing.T) {
	// Frozen clock: every key stays "fresh", which is exactly the case the
	// old lazy sweep could not reclaim.
	l, _ := testLimiter(5, time.Minute, time.Minute)

	const extra = 1_000
	for i := 0; i < maxEntries+extra; i++ {
		l.Attempt(churnKey(i))
	}

	if n := len(l.entries); n > maxEntries {
		t.Fatalf("limiter table unbounded: len=%d after %d distinct keys, want <= cap=%d",
			n, maxEntries+extra, maxEntries)
	}
}

// A key being actively hit must keep rate-limiting correctly even while the
// table is under heavy key churn that forces eviction: the active key stays
// most-recently-used and survives, so its accrued failures still trip the
// lockout, and expiry still releases it.
func TestLimiterBoundedStillLimitsActiveKey(t *testing.T) {
	l, now := testLimiter(3, time.Minute, time.Minute)
	const active = "acct:t1:victim@example.com"

	// Two failures: under the 3-failure threshold, still allowed.
	for i := 0; i < 2; i++ {
		if ok, _ := l.Attempt(active); !ok {
			t.Fatalf("attempt %d on the active key should pass", i+1)
		}
	}

	// Churn well past the cap, keeping the active key warm so LRU eviction
	// targets the idle churn keys, never the one in use.
	for i := 0; i < maxEntries+2_000; i++ {
		l.Attempt(churnKey(i))
		if i%1_000 == 0 {
			l.Allow(active) // touch without recording a failure
		}
	}

	if n := len(l.entries); n > maxEntries {
		t.Fatalf("table unbounded under churn: len=%d > cap=%d", n, maxEntries)
	}

	// The active key survived eviction and its failures still stand: the 3rd
	// attempt trips the lockout.
	if ok, retry := l.Attempt(active); ok || retry <= 0 {
		t.Fatalf("active key not locked after reaching MaxFailures: ok=%v retry=%v", ok, retry)
	}
	// And expiry still works: once the lockout elapses, it flows again.
	*now = now.Add(61 * time.Second)
	if ok, _ := l.Attempt(active); !ok {
		t.Fatal("active key still locked after its lockout expired")
	}
}

// BenchmarkAttempt drives Attempt with a never-repeating key stream. It proves
// the two AUTHZ-13 acceptance properties at scale: the table stays bounded at
// the cap, and per-Attempt cost stays flat (no O(n) sweep) and far under the
// 10µs budget regardless of how many distinct keys have been seen. Force the
// 1M-key case with: go test -run=^$ -bench=BenchmarkAttempt -benchtime=1000000x
func BenchmarkAttempt(b *testing.B) {
	l := NewLimiter(5, time.Minute, time.Minute)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Attempt("ip:" + strconv.Itoa(i))
	}
	b.StopTimer()
	if n := len(l.entries); n > maxEntries {
		b.Fatalf("table unbounded: len=%d > cap=%d after %d distinct keys", n, maxEntries, b.N)
	}
}
