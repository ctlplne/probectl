package lifecycle

import (
	"fmt"
	"testing"
)

func TestParse(t *testing.T) {
	cases := map[string]Version{
		"v1.4.2":         {Major: 1, Minor: 4, Patch: 2},
		"1.4.2":          {Major: 1, Minor: 4, Patch: 2},
		"2.0.0-rc1":      {Major: 2, Minor: 0, Patch: 0, Pre: "rc1"},
		"1.5.0+abc123":   {Major: 1, Minor: 5, Patch: 0},
		"3.2":            {Major: 3, Minor: 2, Patch: 0},
		"0.0.0-dev":      {Dev: true, Pre: "dev"},
		"":               {Dev: true, Pre: "dev"},
		"unknown":        {Dev: true, Pre: "dev"},
		"v1.4.0-dev.123": {Major: 1, Minor: 4, Patch: 0, Pre: "dev.123", Dev: true},
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("Parse(%q) = %+v, want %+v", in, got, want)
		}
	}
	if _, err := Parse("1.x.0"); err == nil {
		t.Fatal("non-numeric component should error")
	}
}

func TestCompare(t *testing.T) {
	mk := func(s string) Version { v, _ := Parse(s); return v }
	if mk("1.4.0").Compare(mk("1.3.9")) != 1 {
		t.Fatal("1.4.0 > 1.3.9")
	}
	if mk("1.4.0").Compare(mk("2.0.0")) != -1 {
		t.Fatal("1.4.0 < 2.0.0")
	}
	if mk("1.4.2").Compare(mk("1.4.2")) != 0 {
		t.Fatal("equal core compares 0 (pre ignored)")
	}
}

// The N/N-1 policy must accept one minor of skew in BOTH directions and reject
// anything wider or across a major boundary.
func TestPolicySkewWindow(t *testing.T) {
	p := DefaultPolicy()
	ok := func(control, agent string) bool { o, _ := p.Check(control, agent); return o }

	// Same version + ±1 minor, both directions.
	for _, c := range []struct{ control, agent string }{
		{"1.4.0", "1.4.3"}, // same minor
		{"1.4.0", "1.3.9"}, // agent one behind (N control, N-1 agent)
		{"1.4.0", "1.5.0"}, // agent one ahead (N agent, N+1 control's peer)
		{"1.5.0", "1.4.0"}, // N+1 control, N agent
	} {
		if !ok(c.control, c.agent) {
			t.Fatalf("control %s should accept agent %s", c.control, c.agent)
		}
	}

	// Too wide a minor skew, and a major mismatch, are rejected.
	for _, c := range []struct{ control, agent string }{
		{"1.4.0", "1.2.0"}, // skew 2
		{"1.4.0", "1.6.0"}, // skew 2 ahead
		{"2.0.0", "1.9.0"}, // major mismatch
	} {
		if accepted, reason := p.Check(c.control, c.agent); accepted {
			t.Fatalf("control %s should REJECT agent %s (reason was %q)", c.control, c.agent, reason)
		}
	}
}

func TestPolicyDevAndFloor(t *testing.T) {
	p := DefaultPolicy()
	// A dev build on either side skips the check (don't break local/CI fleets).
	if ok, _ := p.Check("0.0.0-dev", "1.2.0"); !ok {
		t.Fatal("dev control should skip the skew check")
	}
	if ok, _ := p.Check("1.4.0", ""); !ok {
		t.Fatal("an agent with no version (treated dev) should not be rejected")
	}
	// An unparseable agent version is rejected.
	if ok, _ := p.Check("1.4.0", "garbage.version"); ok {
		t.Fatal("unparseable agent version should be rejected")
	}
	// An explicit floor retires old agents even within the window.
	pf := Policy{Window: 5, Min: "1.4.0"}
	if ok, _ := pf.Check("1.6.0", "1.3.0"); ok {
		t.Fatal("agent below the Min floor must be rejected")
	}
	if ok, _ := pf.Check("1.6.0", "1.4.0"); !ok {
		t.Fatal("agent at the Min floor is allowed")
	}
}

func TestCohortStableAndDistributed(t *testing.T) {
	split := Split{CanaryPercent: 10, EarlyPercent: 30}
	// Stability: same id → same cohort across repeated calls.
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("agent-%d", i)
		first := CohortOf(id, split)
		for r := 0; r < 3; r++ {
			if CohortOf(id, split) != first {
				t.Fatalf("cohort for %s is not stable", id)
			}
		}
	}
	// Distribution: over many agents, the rings roughly match the split.
	counts := map[Cohort]int{}
	const n = 5000
	for i := 0; i < n; i++ {
		counts[CohortOf(fmt.Sprintf("agent-%d", i), split)]++
	}
	// canary ~10%, early ~30%, main ~60% — allow generous tolerance.
	if c := counts[CohortCanary]; c < n*5/100 || c > n*16/100 {
		t.Fatalf("canary share off: %d/%d", c, n)
	}
	if m := counts[CohortMain]; m < n*50/100 {
		t.Fatalf("main share too small: %d/%d", m, n)
	}
}

func TestCohortSplitClamped(t *testing.T) {
	// Over-100 percentages clamp instead of misassigning.
	if CohortOf("x", Split{CanaryPercent: 200, EarlyPercent: 200}) != CohortCanary {
		t.Fatal("an all-canary split should put everyone in canary")
	}
}

// A rollout promotes cohorts one ring at a time; an agent only moves to the target
// once its own ring is released.
func TestRolloutProgression(t *testing.T) {
	split := Split{CanaryPercent: 100} // force every test agent into canary
	earlySplit := Split{EarlyPercent: 100}

	r := Rollout{TargetVersion: "1.5.0", Stage: 0, Split: split}
	if r.Active() {
		t.Fatal("stage 0 is not active")
	}
	if got := r.DesiredVersion("a", "1.4.0"); got != "1.4.0" {
		t.Fatalf("not-started rollout should keep current, got %s", got)
	}

	r.Stage = 1 // canary released
	if !r.Active() || !r.Released(CohortCanary) || r.Released(CohortEarly) {
		t.Fatalf("stage 1 should release canary only: %+v", r)
	}
	if got := r.DesiredVersion("a", "1.4.0"); got != "1.5.0" {
		t.Fatalf("canary agent should get target at stage 1, got %s", got)
	}

	// An early-cohort agent is NOT upgraded until stage 2.
	re := Rollout{TargetVersion: "1.5.0", Stage: 1, Split: earlySplit}
	if got := re.DesiredVersion("a", "1.4.0"); got != "1.4.0" {
		t.Fatalf("early agent should wait at stage 1, got %s", got)
	}
	re.Stage = 2
	if got := re.DesiredVersion("a", "1.4.0"); got != "1.5.0" {
		t.Fatalf("early agent should upgrade at stage 2, got %s", got)
	}

	// Stage 3 releases the whole fleet.
	rm := Rollout{TargetVersion: "1.5.0", Stage: 3, Split: Split{}}
	if got := rm.DesiredVersion("anything", "1.4.0"); got != "1.5.0" {
		t.Fatalf("stage 3 should upgrade everyone, got %s", got)
	}
}
