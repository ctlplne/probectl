// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
