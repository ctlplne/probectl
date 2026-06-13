// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/fairness"
)

// TestNoisyHarnessInstallsFairnessGate is the SCALE-004 acceptance test: the
// noisy-neighbor harness now actually installs the fairness gate it claims to
// validate, and the scale gate's TIMING-INDEPENDENT isolation assertion runs
// (not gated out below the 5ms materiality floor on the microsecond in-memory
// bus). It also encodes the NEGATIVE CONTROL: with fairness disabled the flood
// is NOT shed and the gate must flag it.
func TestNoisyHarnessInstallsFairnessGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	cfg := NoisyConfig{
		QuietResults: 200, NoisyFactor: 10, Producers: 4, Repeats: 1,
		SettleTimeout: 10 * time.Second,
	}

	// (1) WITH the fairness gate: the flood is SHED (admit fraction well below 1)
	// and the quiet tenant stays correct. This is the gate doing its job — and
	// it's a timing-INDEPENDENT signal (we never look at latency).
	gate := fairness.NewGate(fairness.Policy{ResultsPerSec: 1000, BurstSeconds: 1}, nil)
	cfgOn := cfg
	cfgOn.Fairness = gate
	on, err := DriveNoisyNeighbor(ctx, cfgOn)
	if err != nil {
		t.Fatal(err)
	}
	if !on.FairnessOn {
		t.Fatal("report must record that a fairness gate was installed")
	}
	if !on.QuietCorrect {
		t.Fatalf("quiet tenant must stay correct under the gate: %+v", on)
	}
	if on.NoisyPublished == 0 {
		t.Fatal("the noisy tenant must have flooded (the harness must exercise the gate)")
	}
	if on.NoisyAdmitFrac >= maxNoisyAdmitFrac {
		t.Fatalf("fairness gate did NOT shed the flood: admitted %.0f%% of %d (want < %.0f%%)",
			on.NoisyAdmitFrac*100, on.NoisyPublished, maxNoisyAdmitFrac*100)
	}
	// The scale gate's isolation assertion runs and PASSES with the gate on.
	p, _ := ProfileFor(TierM, 1)
	repOn := ScaleReport{Profile: p, AtCIScale: true, Noisy: on}
	repOn.evaluate()
	for _, v := range repOn.Violations {
		if contains(v, "fairness gate did NOT shed") {
			t.Fatalf("isolation assertion wrongly fired with the gate on: %q", v)
		}
	}

	// (2) NEGATIVE CONTROL — fairness DISABLED: the flood is admitted nearly in
	// full. A report that nonetheless CLAIMS FairnessOn (the audited "gate not
	// installed" gap) MUST be flagged by evaluate().
	off, err := DriveNoisyNeighbor(ctx, cfg) // no Fairness
	if err != nil {
		t.Fatal(err)
	}
	if off.FairnessOn {
		t.Fatal("no gate was installed; FairnessOn must be false")
	}
	// The gate must shed MATERIALLY more than the no-gate baseline — i.e. the
	// fairness path actually bounds the flood (not a no-op).
	if !(on.NoisyAdmitFrac < off.NoisyAdmitFrac) {
		t.Fatalf("the gate did not shed more than the ungated baseline (gate %.3f vs none %.3f) — the harness is not exercising fairness",
			on.NoisyAdmitFrac, off.NoisyAdmitFrac)
	}

	// Simulate the exact bug the gate is meant to catch: a report that CLAIMS
	// FairnessOn but where the flood was admitted in full (an uninstalled /
	// ineffective gate, the audited SCALE-004 gap). evaluate() must flag it.
	bug := NoisyReport{
		Ran: true, QuietCorrect: true, FairnessOn: true,
		NoisyPublished: 2000, NoisySeries: 2000, NoisyAdmitFrac: 1.0,
		Inflation: 1, NoisyP95: 200 * time.Microsecond, Pairs: 1,
	}
	repBug := ScaleReport{Profile: p, AtCIScale: true, Noisy: bug}
	repBug.evaluate()
	fired := false
	for _, v := range repBug.Violations {
		if contains(v, "fairness gate did NOT shed") {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("negative control: an unshed flood under a claimed gate must trip the SCALE-004 isolation assertion; violations=%v", repBug.Violations)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
