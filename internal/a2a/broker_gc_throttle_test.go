// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"testing"
	"time"
)

// TestBrokerThrottlesGC locks the AI-01/RTA-02 fix: the pending/session sweep
// runs at most once per gcMinInterval, so a burst of StartSessions from one mesh
// sweeps once rather than once per session (the quadratic CPU the finding was
// reopened on). It is white-box because the throttle is new internal state
// (b.lastGC); the sweep's correctness over the TTL is covered separately by
// TestBrokerReclaimsUnpolledTasksAfterTTL.
func TestBrokerThrottlesGC(t *testing.T) {
	b := NewBroker()
	clock := time.Unix(1_700_000_000, 0).UTC()
	b.now = func() time.Time { return clock }

	// First brokered session runs the sweep (lastGC was zero).
	if _, err := b.StartSession("t", "r1", "i1", "udp", 1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	first := b.lastGC
	if first.IsZero() {
		t.Fatal("first sweep did not run")
	}

	// A burst within the interval must NOT re-sweep (this is what keeps one mesh
	// from scanning the whole pending backlog 4032 times).
	clock = clock.Add(gcMinInterval / 2)
	for i := 0; i < 50; i++ {
		if _, err := b.StartSession("t", "burst", "i", "udp", 1); err != nil {
			t.Fatalf("burst StartSession: %v", err)
		}
	}
	if !b.lastGC.Equal(first) {
		t.Fatalf("sweep ran again within the throttle interval (lastGC moved %v -> %v); a mesh re-scans per session (AI-01/RTA-02)", first, b.lastGC)
	}

	// Once the interval elapses, the next call sweeps again.
	clock = clock.Add(gcMinInterval * 2)
	if _, err := b.StartSession("t", "after", "i", "udp", 1); err != nil {
		t.Fatalf("post-interval StartSession: %v", err)
	}
	if !b.lastGC.After(first) {
		t.Fatal("sweep never ran again after the throttle interval elapsed")
	}
}
