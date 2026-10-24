// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"strings"
	"testing"
	"time"
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

// DPR-310: a question about a host gathers every probe series on it. When one
// test of the host fails while another passes, the passing test's samples are
// context, not corroboration: G4(a)'s answer cited the healthy /readyz test's
// success = 1 and HTTP 200 as "corroborating" the outage of the service on the
// same address. The failing series and the cross-plane signals still
// corroborate, and every item stays in the evidence.
func TestBuiltinDoesNotCiteAPassingProbeAsCorroboration(t *testing.T) {
	at := func(sec int) time.Time { return time.Date(2026, 10, 24, 14, 11, sec, 0, time.UTC) }
	probe := func(id, test, metric string, value float64, sec int) Evidence {
		return Evidence{ID: id, Domain: DomainMetrics, Plane: "metrics", Title: metric, OccurredAt: at(sec),
			Fields: Row{"metric": metric, "value": value, "agent_id": "agent-1", "test_id": test, "target": "127.0.0.1"}}
	}
	evidence := []Evidence{
		{ID: "bgp", Domain: DomainEntities, Plane: "bgp", Severity: "critical", Title: "127.0.0.0/24 announced by unexpected AS65021", OccurredAt: at(2)},
		{ID: "alert", Domain: DomainEntities, Plane: "network", Severity: "critical", Title: "tenant service down firing", OccurredAt: at(27)},
		probe("readyz-ok-old", "test-readyz", "probectl_probe_success", 0, 1), // an old failure, since recovered
		probe("readyz-ok", "test-readyz", "probectl_probe_success", 1, 21),
		probe("readyz-status", "test-readyz", "probectl_probe_http_status", 200, 21),
		probe("service-down", "test-service", "probectl_probe_success", 0, 16),
		probe("service-duration", "test-service", "probectl_probe_duration_seconds", 0.0009, 16),
	}
	syn, err := NewBuiltinModel().Synthesize(context.Background(), SynthesisInput{Question: "Why is the service at 127.0.0.1 failing?", Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	cited := map[string]bool{}
	for _, f := range syn.Findings {
		for _, c := range f.Citations {
			cited[c.EvidenceID] = true
		}
	}
	for _, id := range []string{"readyz-ok", "readyz-status", "readyz-ok-old"} {
		if cited[id] {
			t.Errorf("finding cites %s, a sample of the passing test, as corroboration: %+v", id, syn.Findings)
		}
	}
	for _, id := range []string{"bgp", "alert", "service-down", "service-duration"} {
		if !cited[id] {
			t.Errorf("finding does not cite %s: %+v", id, syn.Findings)
		}
	}
}
