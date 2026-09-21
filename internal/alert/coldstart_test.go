// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"testing"
	"time"
)

// U-047 cold-start contract for the alert engine (ADR docs/adr/volatile-stores.md):
// a fresh engine (a control-plane restart) holds NO firing state and NO
// silences/acks, and RE-DERIVES firing from the metric source on the first
// evaluation. The documented exception — silences/acks are operator inputs,
// not derivable — is proven: a silence applied before "restart" does not
// survive it (the alert reappears firing, un-silenced: fail-safe, louder).
func TestEngineColdStartReDerivesFiringButNotSilences(t *testing.T) {
	h, rule := newActiveHarness(t)

	// Fresh engine: nothing active.
	if got := h.en.Active(); len(got) != 0 {
		t.Fatalf("cold start has %d active alerts, want 0", len(got))
	}

	// Drive it firing and silence it.
	h.value = 250 // > threshold 100
	h.eval(t, rule)
	active := h.en.Active()
	if len(active) != 1 {
		t.Fatalf("after firing, active = %d", len(active))
	}
	if _, err := h.en.Silence(active[0].Fingerprint, time.Hour); err != nil {
		t.Fatalf("silence: %v", err)
	}
	if h.en.Active()[0].SilencedUntil == nil {
		t.Fatal("alert should be silenced")
	}

	// "Restart": a brand-new engine. No state carried.
	h2, rule2 := newActiveHarness(t)
	if got := h2.en.Active(); len(got) != 0 {
		t.Fatalf("post-restart cold start has %d active, want 0", len(got))
	}

	// Re-derive: the same firing condition fires again on the next eval —
	// and is NOT silenced (the silence did not survive the restart, exactly
	// as the ADR documents).
	h2.value = 250
	h2.eval(t, rule2)
	re := h2.en.Active()
	if len(re) != 1 {
		t.Fatalf("firing state did not re-derive: %d active", len(re))
	}
	if re[0].SilencedUntil != nil {
		t.Fatal("silence must NOT survive a restart (documented exception)")
	}
}
