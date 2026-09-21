// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"testing"
	"time"
)

// SCALE-008: jittered reduces a backoff by a random 0–30% so a fleet does not
// reconnect in lockstep. The result must stay within (0.7d, d] and vary.
func TestJitteredBounds(t *testing.T) {
	d := 10 * time.Second
	lo := time.Duration(float64(d) * 0.70)
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		j := jittered(d)
		if j > d || j < lo {
			t.Fatalf("jittered(%v) = %v, want within (%v, %v]", d, j, lo, d)
		}
		seen[j] = true
	}
	if len(seen) < 5 {
		t.Fatalf("jitter produced only %d distinct values — not decorrelating the fleet", len(seen))
	}
	if jittered(0) != 0 {
		t.Fatal("jittered(0) must be 0")
	}
}
