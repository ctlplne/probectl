// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package slo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

var sloT = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

const checkoutSLO = `apiVersion: openslo/v1
kind: SLO
metadata:
  name: checkout-availability
  displayName: Checkout availability
  labels:
    team: payments
spec:
  description: HTTP probes against the checkout edge.
  service: checkout
  indicator:
    metadata:
      name: checkout-probe-success
    spec:
      ratioMetric:
        good:
          metricSource:
            type: probectl
            spec:
              canary_type: http
              target: checkout.acme.example
              outcome: success
        total:
          metricSource:
            type: probectl
            spec:
              canary_type: http
              target: checkout.acme.example
  timeWindow:
    - duration: 30d
      isRolling: true
  budgetingMethod: Occurrences
  objectives:
    - target: 0.99
`

func parsed(t *testing.T) SLO {
	t.Helper()
	s, err := Parse([]byte(checkoutSLO))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --- OpenSLO conformance: import → export round-trip ---

func TestOpenSLORoundTrip(t *testing.T) {
	s := parsed(t)
	if s.Name != "checkout-availability" || s.Service != "checkout" || s.Team != "payments" ||
		s.Objective != 0.99 || s.Window != 30*24*time.Hour || s.CanaryType != "http" {
		t.Fatalf("parsed = %+v", s)
	}
	out, err := s.Export()
	if err != nil {
		t.Fatal(err)
	}
	// Re-import the export: semantically identical (lossless round-trip).
	s2, err := Parse(out)
	if err != nil {
		t.Fatalf("re-import failed: %v\n%s", err, out)
	}
	if s2.Name != s.Name || s2.Objective != s.Objective || s2.Window != s.Window ||
		s2.Service != s.Service || s2.Team != s.Team || s2.Target != s.Target {
		t.Fatalf("round-trip drift:\nin:  %+v\nout: %+v", s, s2)
	}
	// The export still says OpenSLO.
	if !strings.Contains(string(out), "apiVersion: openslo/v1") || !strings.Contains(string(out), "kind: SLO") {
		t.Fatalf("export shape:\n%s", out)
	}
}

func TestOpenSLOStrictness(t *testing.T) {
	cases := map[string]string{
		"wrong apiVersion": strings.Replace(checkoutSLO, "openslo/v1", "openslo/v2alpha", 1),
		"wrong kind":       strings.Replace(checkoutSLO, "kind: SLO", "kind: Service", 1),
		"bad target":       strings.Replace(checkoutSLO, "target: 0.99", "target: 1.5", 1),
		"bad window":       strings.Replace(checkoutSLO, "duration: 30d", "duration: fortnight", 1),
		"calendar window":  strings.Replace(checkoutSLO, "isRolling: true", "isRolling: false", 1),
		"wrong budgeting":  strings.Replace(checkoutSLO, "Occurrences", "Timeslices", 1),
		"unknown field":    checkoutSLO + "  notAField: true\n",
		"missing outcome":  strings.Replace(checkoutSLO, "              outcome: success\n", "", 1),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// --- SLI computation + error budget ---

func TestSLIComputationAndBudget(t *testing.T) {
	e := NewEngine([]SLO{parsed(t)})
	e.clock = func() time.Time { return sloT.Add(100 * time.Minute) }

	// 99% objective; feed 96 good + 4 bad = 96% attainment over the window.
	at := sloT
	for i := 0; i < 100; i++ {
		ok := i%25 != 0 // 4 failures
		e.ObserveResult("t1", "http", "checkout.acme.example", ok, at.Add(time.Duration(i)*time.Minute))
	}
	sts := e.Statuses("t1")
	if len(sts) != 1 {
		t.Fatalf("statuses = %d", len(sts))
	}
	st := sts[0]
	if st.TotalEvents != 100 || st.ColdStart {
		t.Fatalf("events=%d cold=%v", st.TotalEvents, st.ColdStart)
	}
	if st.Attainment < 0.959 || st.Attainment > 0.961 {
		t.Fatalf("attainment = %.4f, want 0.96", st.Attainment)
	}
	// 4% errors against a 1% budget → budget fully exhausted (clamped to 0).
	if st.ErrorBudgetRemaining != 0 {
		t.Fatalf("budget remaining = %.4f, want 0", st.ErrorBudgetRemaining)
	}
	// Mismatched streams never count.
	e.ObserveResult("t1", "dns", "checkout.acme.example", false, sloT)
	e.ObserveResult("t1", "http", "other.example", false, sloT)
	if got := e.Statuses("t1")[0].TotalEvents; got != 100 {
		t.Fatalf("non-matching results counted: %d", got)
	}
	// Tenant isolation: another tenant is cold and empty.
	other := e.Statuses("t2")[0]
	if other.TotalEvents != 0 || !other.ColdStart {
		t.Fatalf("cross-tenant SLI state: %+v", other)
	}
}

// --- multi-window burn-rate alerting ---

// feed pushes n results at a per-minute cadence ending at `end`.
func feed(e *Engine, tenant string, ok bool, n int, end time.Time, gap time.Duration) {
	for i := n - 1; i >= 0; i-- {
		e.ObserveResult(tenant, "http", "checkout.acme.example", ok, end.Add(-time.Duration(i)*gap))
	}
}

func TestBurnRateAlertingMultiWindow(t *testing.T) {
	e := NewEngine([]SLO{parsed(t)})

	// A healthy baseline: 200 successes over ~3.3h.
	end := sloT.Add(4 * time.Hour)
	feed(e, "t1", true, 200, end.Add(-30*time.Minute), time.Minute)

	// HARD OUTAGE: everything fails for 30 minutes (one probe/min). The fast
	// window (1h+5m @14.4x) must fire: 100% errors / 1% budget = burn 100.
	var fired []incident.Signal
	for i := 0; i < 30; i++ {
		fired = append(fired, e.ObserveResult("t1", "http", "checkout.acme.example", false,
			end.Add(time.Duration(i)*time.Minute))...)
	}
	if len(fired) == 0 {
		t.Fatal("hard outage raised no burn alert")
	}
	// The FAST window (1h+5m @14.4x) must fire with page severity during a
	// hard outage; the slow/ticket window may legitimately fire too.
	var fast *incident.Signal
	for i := range fired {
		if fired[i].Attributes["slo.window"] == "fast" {
			fast = &fired[i]
		}
	}
	if fast == nil {
		t.Fatalf("fast window never fired; got %+v", fired)
	}
	if fast.Kind != "slo.burn_rate" || fast.Plane != "slo" || fast.Severity != incident.SeverityCritical {
		t.Fatalf("signal = %+v", fast)
	}
	if fast.Attributes["slo.name"] != "checkout-availability" || fast.Attributes["slo.team"] != "payments" {
		t.Fatalf("attrs = %+v", fast.Attributes)
	}
	// Latching: the same episode never re-fires the same window.
	names := map[string]int{}
	for _, s := range fired {
		names[s.Attributes["slo.window"]]++
	}
	for w, n := range names {
		if n > 1 {
			t.Fatalf("window %s fired %d times in one episode", w, n)
		}
	}

	// The status view shows the firing windows.
	var firing int
	for _, br := range e.Statuses("t1")[0].BurnRates {
		if br.Firing {
			firing++
		}
	}
	if firing == 0 {
		t.Fatal("status shows no firing windows during an outage")
	}
}

func TestBurnRateNoNoiseAndColdStart(t *testing.T) {
	e := NewEngine([]SLO{parsed(t)})
	end := sloT.Add(4 * time.Hour)

	// Cold start: 10 hard failures with no baseline → silent.
	var sigs []incident.Signal
	for i := 0; i < 10; i++ {
		sigs = append(sigs, e.ObserveResult("t1", "http", "checkout.acme.example", false,
			end.Add(time.Duration(i)*time.Second))...)
	}
	if len(sigs) != 0 {
		t.Fatalf("cold start alerted: %+v", sigs)
	}
	if !e.Statuses("t1")[0].ColdStart {
		t.Fatal("cold_start flag missing")
	}

	// A blip on a healthy stream: 1 failure in 200 (0.5% errors ≈ burn 0.5
	// against the 1% budget) → quiet on every window.
	e2 := NewEngine([]SLO{parsed(t)})
	feed(e2, "t1", true, 199, end, time.Minute)
	if got := e2.ObserveResult("t1", "http", "checkout.acme.example", false, end.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("single blip alerted: %+v", got)
	}
}

// --- the S43 what-if seam ---

func TestImpactedSLOs(t *testing.T) {
	e := NewEngine([]SLO{parsed(t)})
	got := e.ImpactedSLOs("t1", []string{"service:checkout"}, nil)
	if len(got) != 1 || got[0] != "checkout-availability" {
		t.Fatalf("by service: %v", got)
	}
	got = e.ImpactedSLOs("t1", nil, []string{"host:checkout.acme.example"})
	if len(got) != 1 {
		t.Fatalf("by host: %v", got)
	}
	if got = e.ImpactedSLOs("t1", []string{"service:unrelated"}, []string{"host:198.51.100.1"}); len(got) != 0 {
		t.Fatalf("unrelated impact: %v", got)
	}
}

// --- loader ---

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	second := strings.Replace(checkoutSLO, "checkout-availability", "checkout-latency", 1)
	if err := os.WriteFile(filepath.Join(dir, "slos.yaml"),
		[]byte(checkoutSLO+"\n---\n"+second), 0o600); err != nil {
		t.Fatal(err)
	}
	slos, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(slos) != 2 {
		t.Fatalf("loaded %d", len(slos))
	}
	// Duplicates and malformed files fail closed.
	if err := os.WriteFile(filepath.Join(dir, "dup.yaml"), []byte(checkoutSLO), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate accepted: %v", err)
	}
	if _, err := LoadDir("/does/not/exist"); err == nil {
		t.Fatal("missing dir accepted")
	}
	if got, err := LoadDir(""); err != nil || got != nil {
		t.Fatalf("empty dir config: %v %v", got, err)
	}
}

func TestLoadDirBoundsDefinitionFile(t *testing.T) {
	const boundary = maxDefinitionFileBytes
	definitionAtSize := func(t *testing.T, size int) []byte {
		t.Helper()
		if size < len(checkoutSLO)+2 {
			t.Fatalf("definition fixture size %d is too small", size)
		}
		return []byte(checkoutSLO + "\n#" + strings.Repeat("x", size-len(checkoutSLO)-2))
	}

	t.Run("maximum valid", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(dir, "maximum.yaml"),
			definitionAtSize(t, boundary),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		definitions, err := LoadDir(dir)
		if err != nil || len(definitions) != 1 {
			t.Fatalf("maximum-valid definition: definitions=%d err=%v", len(definitions), err)
		}
	})

	t.Run("one past", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(dir, "oversized.yaml"),
			definitionAtSize(t, boundary+1),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDir(dir); err == nil ||
			!strings.Contains(err.Error(), "exceeds 1048576-byte limit") {
			t.Fatalf("one-past definition error = %v, want explicit size refusal", err)
		}
	})
}

func TestParseWindow(t *testing.T) {
	cases := map[string]time.Duration{"30d": 720 * time.Hour, "4w": 672 * time.Hour, "12h": 12 * time.Hour, "30m": 30 * time.Minute}
	for raw, want := range cases {
		got, err := ParseWindow(raw)
		if err != nil || got != want {
			t.Errorf("ParseWindow(%s) = %v, %v", raw, got, err)
		}
	}
	for _, bad := range []string{"", "d", "30", "-3d", "3y"} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("ParseWindow(%q) accepted", bad)
		}
	}
}

func ExampleSLO_Matches() {
	s := SLO{Target: "api.*", CanaryType: "http"}
	fmt.Println(s.Matches("http", "api.acme.example"), s.Matches("dns", "api.acme.example"))
	// Output: true false
}
