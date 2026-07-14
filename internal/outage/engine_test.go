// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package outage

import (
	"strings"
	"testing"
	"time"
)

// asnResolver maps test IPs into AS64500 / AS64501 deterministically.
func asnResolver(ip string) (Scope, bool) {
	switch {
	case strings.HasPrefix(ip, "10.1."):
		return Scope{Kind: ScopeASN, Code: "AS64500", Name: "Testland Telecom"}, true
	case strings.HasPrefix(ip, "10.2."):
		return Scope{Kind: ScopeASN, Code: "AS64501", Name: "Otherland Net"}, true
	default:
		return Scope{}, false
	}
}

// fail / pass feed n results for a target into the engine.
func feed(e *Engine, tenant, target, ip string, ok bool, n int, from time.Time) (sigs int, last time.Time) {
	var all int
	t := from
	for i := 0; i < n; i++ {
		s := e.Observe(tenant, "icmp", target, ip, ok, t)
		all += len(s)
		last = t
		t = t.Add(time.Minute)
	}
	return all, last
}

func TestVantageDetectionFiresLatchedAndClears(t *testing.T) {
	e := NewEngine(nil, asnResolver)
	e.clock = func() time.Time { return at(30) }
	start := at(0)

	// One failing target is NOT an outage (could be the target itself).
	if n, _ := feed(e, "t1", "a.example:443", "10.1.0.1", false, 3, start); n != 0 {
		t.Fatalf("single failing target must not fire, got %d signals", n)
	}

	// A second distinct target in the same ASN failing → exactly one latched signal.
	var total int
	tm := start
	for i := 0; i < 3; i++ {
		total += len(e.Observe("t1", "http", "b.example:443", "10.1.0.2", false, tm))
		tm = tm.Add(time.Minute)
	}
	if total != 1 {
		t.Fatalf("want exactly one latched vantage signal, got %d", total)
	}

	// Recovery clears the episode into history and re-arms.
	clearAt := at(40)
	e.clock = func() time.Time { return at(55) }
	feed(e, "t1", "a.example:443", "10.1.0.1", true, 8, clearAt)
	feed(e, "t1", "b.example:443", "10.1.0.2", true, 8, clearAt)
	snap := e.Snapshot("t1")
	if len(snap.Vantage) != 1 || snap.Vantage[0].Ongoing {
		t.Fatalf("episode must clear into history, got %+v", snap.Vantage)
	}
	if snap.Vantage[0].End.IsZero() {
		t.Error("cleared episode must record its end")
	}

	// Re-armed: a fresh two-target failure burst fires again.
	again := at(60)
	n1, _ := feed(e, "t1", "a.example:443", "10.1.0.1", false, 3, again)
	n2, _ := feed(e, "t1", "b.example:443", "10.1.0.2", false, 3, again.Add(time.Second))
	if n1+n2 != 1 {
		t.Fatalf("re-armed episode must fire exactly once more, got %d", n1+n2)
	}
}

func TestVantageSignalShape(t *testing.T) {
	e := NewEngine(nil, asnResolver)
	start := at(0)
	feed(e, "t1", "a.example:443", "10.1.0.1", false, 2, start)
	var sig = e.Observe("t1", "http", "b.example:443", "10.1.0.2", false, start.Add(time.Minute))
	sig = append(sig, e.Observe("t1", "http", "b.example:443", "10.1.0.2", false, start.Add(2*time.Minute))...)
	if len(sig) != 1 {
		t.Fatalf("want 1 signal, got %d", len(sig))
	}
	s := sig[0]
	if s.TenantID != "t1" || s.Plane != "outage" || s.Kind != "outage.vantage_detected" {
		t.Errorf("signal identity wrong: %+v", s)
	}
	if s.Attributes["outage.scope"] != "AS64500" || s.Attributes["outage.failing_targets"] != "2" {
		t.Errorf("signal attributes wrong: %+v", s.Attributes)
	}
}

func TestScopesDoNotCrossContaminate(t *testing.T) {
	e := NewEngine(nil, asnResolver)
	start := at(0)
	// One failing target in EACH of two ASNs — neither reaches minTargets.
	n1, _ := feed(e, "t1", "a.example:443", "10.1.0.1", false, 4, start)
	n2, _ := feed(e, "t1", "c.example:443", "10.2.0.1", false, 4, start)
	if n1+n2 != 0 {
		t.Fatalf("failures across different scopes must not aggregate, got %d", n1+n2)
	}
}

func TestNoResolverMeansNoVantage(t *testing.T) {
	e := NewEngine(NewStore(0), nil)
	if n, _ := feed(e, "t1", "a.example:443", "10.1.0.1", false, 5, at(0)); n != 0 {
		t.Fatalf("nil resolver must be a no-op, got %d signals", n)
	}
	if snap := e.Snapshot("t1"); snap.ScopeResolution {
		t.Fatal("snapshot must report scope_resolution=false")
	}
}

func TestExternalCorrelationLatchedPerEvent(t *testing.T) {
	store := NewStore(0)
	store.clock = func() time.Time { return at(30) }
	store.SetEvents("ioda", []Event{extEvent("ioda:as64500", Scope{Kind: ScopeASN, Code: "AS64500"}, at(-10), time.Time{})})
	e := NewEngine(store, asnResolver)

	// First failing observation inside the event scope correlates — once.
	sigs := e.Observe("t1", "icmp", "a.example:443", "10.1.0.1", false, at(5))
	if len(sigs) != 1 || sigs[0].Kind != "outage.external_correlated" {
		t.Fatalf("want one correlation signal, got %+v", sigs)
	}
	if sigs[0].Attributes["outage.event_id"] != "ioda:as64500" || sigs[0].Target != "a.example:443" {
		t.Errorf("correlation evidence wrong: %+v", sigs[0])
	}
	// Repeat failures and other targets in scope do NOT re-alert the same event.
	more := e.Observe("t1", "icmp", "a.example:443", "10.1.0.1", false, at(6))
	more = append(more, e.Observe("t1", "http", "b.example:443", "10.1.0.2", false, at(7))...)
	for _, s := range more {
		if s.Kind == "outage.external_correlated" {
			t.Fatalf("correlation must latch per event, got extra %+v", s)
		}
	}
	// A success never correlates.
	if sigs := e.Observe("t2", "icmp", "ok.example:443", "10.1.0.9", true, at(8)); len(sigs) != 0 {
		t.Fatalf("success must not correlate, got %+v", sigs)
	}
}

func TestSnapshotAffectedTestsAndTenantIsolation(t *testing.T) {
	store := NewStore(0)
	store.clock = func() time.Time { return at(30) }
	store.SetEvents("ioda", []Event{extEvent("ioda:as64500", Scope{Kind: ScopeASN, Code: "AS64500"}, at(-10), time.Time{})})
	e := NewEngine(store, asnResolver)
	e.clock = func() time.Time { return at(10) }

	feed(e, "tenant-a", "a.example:443", "10.1.0.1", false, 3, at(5))
	feed(e, "tenant-b", "b.example:443", "10.1.0.2", false, 3, at(5))

	// THE S47a exit criterion: the external event correlates with the
	// caller's affected tests — and ONLY the caller's (guardrail 1).
	a := e.Snapshot("tenant-a")
	if len(a.Events) != 1 || !a.Events[0].Ongoing {
		t.Fatalf("tenant-a must see the shared external event, got %+v", a.Events)
	}
	aff := a.Events[0].Affected
	if len(aff) != 1 || aff[0].Target != "a.example:443" || aff[0].Failures != 3 {
		t.Fatalf("tenant-a affected tests wrong: %+v", aff)
	}
	b := e.Snapshot("tenant-b")
	if len(b.Events[0].Affected) != 1 || b.Events[0].Affected[0].Target != "b.example:443" {
		t.Fatalf("tenant-b must see only its own impact: %+v", b.Events[0].Affected)
	}
	for _, view := range a.Events[0].Affected {
		if view.Target == "b.example:443" {
			t.Fatal("cross-tenant affected-test leak")
		}
	}
	// Vantage detections are tenant-private too.
	if len(a.Vantage) != 0 {
		for _, v := range a.Vantage {
			if strings.Contains(v.ID, "tenant-b") {
				t.Fatal("cross-tenant vantage leak")
			}
		}
	}
}

func TestEngineBoundsTargets(t *testing.T) {
	e := NewEngine(nil, asnResolver)
	start := at(0)
	for i := 0; i < maxTargetsPerTen+50; i++ {
		e.Observe("t1", "icmp", string(rune('a'+i%26))+string(rune('0'+i%10))+strings.Repeat("x", i%7)+".example", "10.1.0.1", true, start)
	}
	e.mu.Lock()
	n := len(e.tenants["t1"].targets)
	e.mu.Unlock()
	if n > maxTargetsPerTen {
		t.Fatalf("target index must stay bounded, got %d", n)
	}
}

func TestObserveDropsUnscopedAndUnresolved(t *testing.T) {
	e := NewEngine(nil, asnResolver)
	if sigs := e.Observe("", "icmp", "a.example", "10.1.0.1", false, at(0)); sigs != nil {
		t.Error("empty tenant must be dropped (guardrail 1)")
	}
	if sigs := e.Observe("t1", "icmp", "a.example", "203.0.113.9", false, at(0)); sigs != nil {
		t.Error("unresolvable peer must be a no-op")
	}
}
