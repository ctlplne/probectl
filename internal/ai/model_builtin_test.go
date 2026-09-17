// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"context"
	"strings"
	"testing"
)

// DPR-143: DPR-061 established that an unmeasured layer reported as healthy is a
// guess and must be reported as one. The cross-plane root cause is the product's
// highest-stakes verdict and it did not follow that rule: one built from a single
// plane while four others said nothing read exactly like one built from five
// where four were clean.
func TestBuiltinNamesThePlanesThatSaidNothing(t *testing.T) {
	m := NewBuiltinModel()
	syn, err := m.Synthesize(context.Background(), SynthesisInput{
		Question: "why is checkout slow",
		Evidence: []Evidence{
			{ID: "e1", Plane: "bgp", Severity: "critical", Title: "origin change on 10.0.0.0/8"},
		},
	})
	if err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	// bgp spoke; the other cause-bearing planes did not.
	if len(syn.Silent) == 0 {
		t.Fatal("a single-plane verdict must name the planes that contributed nothing")
	}
	for _, want := range []string{"change", "path", "threat", "events"} {
		found := false
		for _, s := range syn.Silent {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Errorf("silent planes %v should include %q", syn.Silent, want)
		}
	}
	for _, unwanted := range []string{"bgp", "routing"} {
		for _, s := range syn.Silent {
			if s == unwanted {
				t.Errorf("%q spoke; it must not be listed as silent: %v", unwanted, syn.Silent)
			}
		}
	}
	// And it has to say so in words, not only in a field a UI might ignore.
	if !strings.Contains(syn.RootCause, "unverified rather than clean") {
		t.Errorf("the headline must say the silent layers are unverified: %q", syn.RootCause)
	}
	// A verdict resting on one plane while others were silent cannot be high.
	if syn.Confidence == ConfidenceHigh {
		t.Error("a single-plane verdict with silent planes must not claim high confidence")
	}
}

// A plane speaking under either of its two labels counts as that plane speaking:
// routing/bgp and network/path are the same plane, and listing one as silent
// because the evidence used the other label would be a false alarm.
func TestBuiltinTreatsPlaneAliasesAsOnePlane(t *testing.T) {
	m := NewBuiltinModel()
	syn, err := m.Synthesize(context.Background(), SynthesisInput{
		Question: "why is checkout slow",
		Evidence: []Evidence{
			{ID: "e1", Plane: "routing", Severity: "critical", Title: "withdrawal"},
			{ID: "e2", Plane: "network", Severity: "warning", Title: "latency on a hop"},
		},
	})
	if err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	for _, alias := range []string{"bgp", "path"} {
		for _, s := range syn.Silent {
			if s == alias {
				t.Errorf("%q spoke under its alias; silent=%v", alias, syn.Silent)
			}
		}
	}
}

// Corroboration across every cause-bearing plane leaves nothing silent, and the
// headline must not carry the caveat at all.
func TestBuiltinSaysNothingWhenEveryPlaneSpoke(t *testing.T) {
	m := NewBuiltinModel()
	var ev []Evidence
	for i, p := range []string{"change", "bgp", "path", "threat", "events"} {
		ev = append(ev, Evidence{ID: "e" + string(rune('1'+i)), Plane: p, Severity: "warning", Title: p + " signal"})
	}
	syn, err := m.Synthesize(context.Background(), SynthesisInput{Question: "why", Evidence: ev})
	if err != nil {
		t.Fatalf("synthesize: %v", err)
	}
	if len(syn.Silent) != 0 {
		t.Errorf("nothing should be silent, got %v", syn.Silent)
	}
	if strings.Contains(syn.RootCause, "No signal from") {
		t.Errorf("no caveat belongs on a fully corroborated verdict: %q", syn.RootCause)
	}
}
