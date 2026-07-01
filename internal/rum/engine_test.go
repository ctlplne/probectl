// SPDX-License-Identifier: LicenseRef-probectl-TBD

package rum

import (
	"fmt"
	"testing"
	"time"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

func at(minutes int) time.Time {
	return time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC).Add(time.Duration(minutes) * time.Minute)
}

func view(tenant, app, host, page string, errors bool, lcpMs float64, when time.Time) *resultv1.Result {
	metrics := map[string]float64{"rum.errors": 0}
	if errors {
		metrics["rum.errors"] = 1
	}
	if lcpMs > 0 {
		metrics["rum.lcp_ms"] = lcpMs
	}
	return &resultv1.Result{
		TenantId: tenant, CanaryType: "rum", ServerAddress: host,
		Success: !errors, StartTimeUnixNano: when.UnixNano(), Metrics: metrics,
		Attributes: map[string]string{"rum.app": app, "url.path": page, "browser.name": "chrome"},
	}
}

// pump feeds n views split between two pages, errRatio of them erroring.
func pump(e *Engine, tenant, app, host string, n int, errEvery int, lcpMs float64, from time.Time) []string {
	var kinds []string
	for i := 0; i < n; i++ {
		erroring := errEvery > 0 && i%errEvery == 0
		page := "/home"
		if i%2 == 1 {
			page = "/checkout/:id"
		}
		when := from.Add(time.Duration(i*3) * time.Second)
		for _, s := range e.ObserveRUM(view(tenant, app, host, page, erroring, lcpMs, when)) {
			kinds = append(kinds, s.Kind)
		}
	}
	return kinds
}

func TestHealthyTrafficNoSignals(t *testing.T) {
	e := NewEngine()
	if kinds := pump(e, "t1", "shop", "web.acme.example", 40, 0, 1200, at(0)); len(kinds) != 0 {
		t.Fatalf("healthy traffic must not signal, got %v", kinds)
	}
	e.clock = func() time.Time { return at(3) }
	snap := e.Snapshot("t1")
	if len(snap.Apps) != 1 || snap.Apps[0].Verdict != VerdictHealthy {
		t.Fatalf("want healthy verdict, got %+v", snap.Apps)
	}
	if snap.Apps[0].WindowViews != 40 || snap.Apps[0].SyntheticObserved {
		t.Fatalf("aggregate wrong: %+v", snap.Apps[0])
	}
}

// THE S47b exit criterion: synthetic and RUM degrade for the same service →
// the confirmed verdict + one latched correlation signal.
func TestUserImpactConfirmedCorrelation(t *testing.T) {
	e := NewEngine()
	e.clock = func() time.Time { return at(10) }

	// Synthetics against the host start failing.
	for i := 0; i < 4; i++ {
		if sigs := e.ObserveSynthetic("t1", "web.acme.example", false, at(i)); len(sigs) != 0 {
			t.Fatalf("synthetic alone must not signal from the RUM engine, got %+v", sigs)
		}
	}
	// Real users are erroring too (every 4th view = 25% > 10%).
	kinds := pump(e, "t1", "shop", "web.acme.example", 40, 4, 1500, at(5))
	confirmed := 0
	for _, k := range kinds {
		if k == "rum.user_impact_correlated" {
			confirmed++
		}
	}
	if confirmed != 1 {
		t.Fatalf("want exactly one latched correlation signal, got %d (%v)", confirmed, kinds)
	}
	snap := e.Snapshot("t1")
	if snap.Apps[0].Verdict != VerdictUserImpactConfirmed {
		t.Fatalf("verdict = %s want %s", snap.Apps[0].Verdict, VerdictUserImpactConfirmed)
	}
	if snap.Apps[0].EvidenceTrust != "synthetic_corroborated" {
		t.Fatalf("evidence trust = %q want synthetic_corroborated", snap.Apps[0].EvidenceTrust)
	}
	if !snap.Apps[0].SyntheticObserved || !snap.Apps[0].SyntheticDegraded || !snap.Apps[0].RUMDegraded {
		t.Fatalf("plane states wrong: %+v", snap.Apps[0])
	}
}

func TestSyntheticOnlyIsHonestlyAnnotatedNotPaged(t *testing.T) {
	e := NewEngine()
	e.clock = func() time.Time { return at(10) }
	for i := 0; i < 4; i++ {
		e.ObserveSynthetic("t1", "web.acme.example", false, at(i))
	}
	// Users are fine.
	if kinds := pump(e, "t1", "shop", "web.acme.example", 40, 0, 1200, at(5)); len(kinds) != 0 {
		t.Fatalf("synthetic-only degradation must not raise a RUM signal, got %v", kinds)
	}
	snap := e.Snapshot("t1")
	if snap.Apps[0].Verdict != VerdictSyntheticOnly {
		t.Fatalf("verdict = %s want %s", snap.Apps[0].Verdict, VerdictSyntheticOnly)
	}
}

func TestUserOnlyBlindSpotIsVisibleButNotPaged(t *testing.T) {
	e := NewEngine()
	e.clock = func() time.Time { return at(10) }
	// Synthetics green for the host.
	for i := 0; i < 4; i++ {
		e.ObserveSynthetic("t1", "web.acme.example", true, at(i))
	}
	// Users degraded by poor LCP (no errors at all).
	kinds := pump(e, "t1", "shop", "web.acme.example", 40, 0, 5200, at(5))
	if len(kinds) != 0 {
		t.Fatalf("RUM-only blind spots are visible but not incident signals, got %v", kinds)
	}
	if snap := e.Snapshot("t1"); snap.Apps[0].Verdict != VerdictUserOnly || snap.Apps[0].EvidenceTrust != "rum_only_low_trust" {
		t.Fatalf("blind-spot status = %+v, want low-trust user-only verdict", snap.Apps[0])
	}
}

func TestRecoveryReArms(t *testing.T) {
	e := NewEngine()
	// Degrade with independent synthetic corroboration …
	for i := 0; i < 4; i++ {
		e.ObserveSynthetic("t1", "web.acme.example", false, at(i))
	}
	kinds := pump(e, "t1", "shop", "web.acme.example", 30, 2, 1500, at(5))
	if len(kinds) != 1 {
		t.Fatalf("want one signal, got %v", kinds)
	}
	// … recover (a healthy window evaluates after the bad one ages out) …
	pump(e, "t1", "shop", "web.acme.example", 30, 0, 1000, at(20))
	// … degrade again with fresh synthetic corroboration: the latch must have
	// re-armed.
	for i := 0; i < 4; i++ {
		e.ObserveSynthetic("t1", "web.acme.example", false, at(35+i))
	}
	kinds = pump(e, "t1", "shop", "web.acme.example", 30, 2, 1500, at(40))
	if len(kinds) != 1 {
		t.Fatalf("re-armed episode must signal once more, got %v", kinds)
	}
}

func TestMinViewsGateNoVerdictFromTrickle(t *testing.T) {
	e := NewEngine()
	e.clock = func() time.Time { return at(1) }
	// 5 views, all erroring — below minViews: never called degraded.
	if kinds := pump(e, "t1", "shop", "web.acme.example", 5, 1, 0, at(0)); len(kinds) != 0 {
		t.Fatalf("a trickle must not be called degraded, got %v", kinds)
	}
	if snap := e.Snapshot("t1"); snap.Apps[0].RUMDegraded {
		t.Fatal("5 views cannot be degraded (minViews gate)")
	}
}

func TestTenantIsolation(t *testing.T) {
	e := NewEngine()
	e.clock = func() time.Time { return at(2) }
	pump(e, "tenant-a", "shop", "web.acme.example", 25, 0, 1000, at(0))
	pump(e, "tenant-b", "intranet", "internal.example", 25, 0, 1000, at(0))

	a, b := e.Snapshot("tenant-a"), e.Snapshot("tenant-b")
	if len(a.Apps) != 1 || a.Apps[0].App != "shop" {
		t.Fatalf("tenant-a sees %+v", a.Apps)
	}
	if len(b.Apps) != 1 || b.Apps[0].App != "intranet" {
		t.Fatalf("tenant-b sees %+v", b.Apps)
	}
	for _, app := range a.Apps {
		if app.Host == "internal.example" {
			t.Fatal("cross-tenant app leak")
		}
	}
	// Rejection counters are tenant-scoped too.
	e.RecordReject("tenant-a", RejectNoConsent)
	if e.Snapshot("tenant-b").Privacy.RejectedNoConsent != 0 {
		t.Fatal("cross-tenant privacy-counter leak")
	}
	// Unscoped records are dropped (guardrail 1).
	if sigs := e.ObserveRUM(view("", "x", "h.example", "/", true, 0, at(0))); sigs != nil {
		t.Fatal("unscoped RUM record must be dropped")
	}
	if sigs := e.ObserveSynthetic("", "h.example", false, at(0)); sigs != nil {
		t.Fatal("unscoped synthetic record must be dropped")
	}
}

func TestPrivacyCountersServeHonesty(t *testing.T) {
	e := NewEngine()
	e.RecordReject("t1", RejectNoConsent)
	e.RecordReject("t1", RejectNoConsent)
	e.RecordReject("t1", RejectMalformed)
	pump(e, "t1", "shop", "web.acme.example", 3, 0, 0, at(0))
	e.clock = func() time.Time { return at(1) }

	p := e.Snapshot("t1").Privacy
	if !p.ConsentRequired || !p.URLRedaction || p.IPStored {
		t.Fatalf("privacy posture wrong: %+v", p)
	}
	if p.RejectedNoConsent != 2 || p.RejectedMalformed != 1 || p.AcceptedPageViews != 3 {
		t.Fatalf("counters wrong: %+v", p)
	}
}

func TestBoundsAppsPagesAndWindows(t *testing.T) {
	e := NewEngine()
	now := at(0)
	for i := 0; i < maxAppsPerTenant+10; i++ {
		e.ObserveRUM(view("t1", fmt.Sprintf("app-%d", i), "h.example", "/", false, 0, now))
	}
	e.mu.Lock()
	apps := len(e.tenants["t1"].apps)
	e.mu.Unlock()
	if apps > maxAppsPerTenant {
		t.Fatalf("apps must stay bounded, got %d", apps)
	}
	// Page overflow lumps into "(other)".
	for i := 0; i < maxPagesPerApp+10; i++ {
		e.ObserveRUM(view("t1", "app-0", "h.example", fmt.Sprintf("/p%d", i), false, 0, now))
	}
	e.mu.Lock()
	pages := len(e.tenants["t1"].apps["app-0|h.example"].pages)
	e.mu.Unlock()
	if pages > maxPagesPerApp+1 {
		t.Fatalf("pages must stay bounded, got %d", pages)
	}
	// Old views age out of the window.
	e.clock = func() time.Time { return at(60) }
	for _, app := range e.Snapshot("t1").Apps {
		t.Fatalf("aged-out windows must render no apps, got %+v", app)
	}
}

func TestPageStatsAggregation(t *testing.T) {
	e := NewEngine()
	e.clock = func() time.Time { return at(2) }
	pump(e, "t1", "shop", "web.acme.example", 30, 3, 2000, at(0))
	snap := e.Snapshot("t1")
	if len(snap.Apps[0].Pages) != 2 {
		t.Fatalf("want 2 page groups, got %+v", snap.Apps[0].Pages)
	}
	if snap.Apps[0].Pages[0].Views < snap.Apps[0].Pages[1].Views {
		t.Fatal("pages must sort by views desc")
	}
	if snap.Apps[0].P75LCPms != 2000 {
		t.Fatalf("p75 lcp = %v want 2000", snap.Apps[0].P75LCPms)
	}
}
