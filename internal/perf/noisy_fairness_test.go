// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/fairness"
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

	// (1) The harness INSTALLS + EXERCISES the gate. Only timing-INDEPENDENT
	// signals are asserted from the harness: that a gate was installed, the quiet
	// tenant stayed correct, and the noisy tenant actually flooded. The harness's
	// wall-clock admit FRACTION is deliberately NOT asserted here — it is
	// execution-speed sensitive (a rate-limited bucket refills more over a slower
	// run), which made this test flake under `-race`. The deterministic shed
	// proof is step (3).
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

	// (2) NEGATIVE CONTROL — fairness DISABLED: the report must not claim a gate.
	off, err := DriveNoisyNeighbor(ctx, cfg) // no Fairness
	if err != nil {
		t.Fatal(err)
	}
	if off.FairnessOn {
		t.Fatal("no gate was installed; FairnessOn must be false")
	}

	// (3) DETERMINISTIC, timing-INDEPENDENT proof that the gate sheds a flood and
	// isolates the quiet tenant. A FROZEN clock means the token bucket never
	// refills, so a `flood`-message burst against a `burst`-capacity bucket admits
	// EXACTLY the capacity and sheds the remainder — identical under `-race` or
	// not. The quiet tenant has its own per-tenant bucket and is fully admitted.
	const flood, burst = 2000, 1000 // capacity = ResultsPerSec(1000) × BurstSeconds(1)
	fixed := time.Unix(1_700_000_000, 0)
	dg := fairness.NewGate(fairness.Policy{ResultsPerSec: 1000, BurstSeconds: 1}, nil).
		WithNow(func() time.Time { return fixed })
	admittedNoisy := 0
	for i := 0; i < flood; i++ {
		if dg.AdmitN(ctx, "noisy", fairness.MeterResults, 1) {
			admittedNoisy++
		}
	}
	if admittedNoisy != burst {
		t.Fatalf("frozen-clock gate must admit exactly the burst capacity %d of a %d flood and shed the rest; admitted %d", burst, flood, admittedNoisy)
	}
	admittedQuiet := 0
	for i := 0; i < 200; i++ {
		if dg.AdmitN(ctx, "quiet", fairness.MeterResults, 1) {
			admittedQuiet++
		}
	}
	if admittedQuiet != 200 {
		t.Fatalf("quiet tenant has its own bucket and must be fully admitted (isolation); got %d/200", admittedQuiet)
	}

	// (4) The SCALE-004 isolation assertion in evaluate() must NOT fire on a
	// well-shed report, and MUST fire on a report that CLAIMS FairnessOn yet
	// admitted the flood in full (the audited "gate not installed/ineffective"
	// gap). Both are checked with CONSTRUCTED reports so the assertion is
	// deterministic, independent of harness wall-clock timing.
	p, _ := ProfileFor(TierM, 1)
	good := NoisyReport{
		Ran: true, QuietCorrect: true, FairnessOn: true,
		NoisyPublished: 2000, NoisySeries: 1000, NoisyAdmitFrac: 0.5,
		Inflation: 1, NoisyP95: 200 * time.Microsecond, Pairs: 1,
	}
	repGood := ScaleReport{Profile: p, AtCIScale: true, Noisy: good}
	repGood.evaluate()
	for _, v := range repGood.Violations {
		if contains(v, "fairness gate did NOT shed") {
			t.Fatalf("isolation assertion wrongly fired on a well-shed report: %q", v)
		}
	}
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
