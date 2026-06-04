package threat

import (
	"fmt"
	"testing"
	"time"
)

func posture(target string, sev Severity, at time.Time, notAfter time.Time) Posture {
	return Posture{
		Target: target, Source: "http", TLSVersion: "1.3", Severity: sev,
		Leaf: &Certificate{Subject: "CN=" + target, NotAfter: notAfter}, ObservedAt: at,
	}
}

func TestPostureStoreLatestWinsAndTenantScoping(t *testing.T) {
	s := NewPostureStore(0)
	t0 := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	s.Record("t-a", posture("web.example:443", SeverityInfo, t0, t0.Add(90*24*time.Hour)))
	s.Record("t-a", posture("web.example:443", SeverityCritical, t0.Add(time.Minute), t0.Add(24*time.Hour)))
	// Out-of-order older observation never overwrites the newer one.
	s.Record("t-a", posture("web.example:443", SeverityInfo, t0.Add(-time.Hour), t0.Add(90*24*time.Hour)))
	// Another tenant's data lands in its own partition.
	s.Record("t-b", posture("secret.other:443", SeverityWarning, t0, t0.Add(time.Hour)))
	// Unscoped records are dropped (fail closed).
	s.Record("", posture("ghost:443", SeverityInfo, t0, t0))
	s.Record("t-a", Posture{Target: "", ObservedAt: t0})

	got := s.List("t-a")
	if len(got) != 1 || got[0].Severity != SeverityCritical {
		t.Fatalf("t-a inventory = %+v", got)
	}
	for _, p := range got {
		if p.Target == "secret.other:443" {
			t.Fatal("CROSS-TENANT LEAK in List")
		}
	}
	if s.Len("t-b") != 1 || s.Len("") != 0 {
		t.Fatalf("partition sizes: t-b=%d empty=%d", s.Len("t-b"), s.Len(""))
	}
}

func TestPostureStoreOrderingAndEviction(t *testing.T) {
	s := NewPostureStore(3)
	t0 := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	s.Record("t", posture("clean:443", SeverityInfo, t0.Add(3*time.Minute), t0.Add(60*24*time.Hour)))
	s.Record("t", posture("warn:443", SeverityWarning, t0.Add(2*time.Minute), t0.Add(10*24*time.Hour)))
	s.Record("t", posture("crit:443", SeverityCritical, t0.Add(time.Minute), t0.Add(-time.Hour)))

	got := s.List("t")
	if got[0].Target != "crit:443" || got[1].Target != "warn:443" || got[2].Target != "clean:443" {
		t.Fatalf("order = %v, %v, %v", got[0].Target, got[1].Target, got[2].Target)
	}

	// Capacity eviction drops the stalest target (crit:443, observed earliest).
	s.Record("t", posture("new:443", SeverityInfo, t0.Add(4*time.Minute), t0.Add(30*24*time.Hour)))
	if s.Len("t") != 3 {
		t.Fatalf("len = %d, want 3", s.Len("t"))
	}
	for _, p := range s.List("t") {
		if p.Target == "crit:443" {
			t.Fatal("stalest target not evicted")
		}
	}
}

func TestPostureStoreBoundedUnderChurn(t *testing.T) {
	s := NewPostureStore(10)
	t0 := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		s.Record("t", posture(fmt.Sprintf("host-%d:443", i), SeverityInfo, t0.Add(time.Duration(i)*time.Second), t0.Add(time.Hour)))
	}
	if s.Len("t") != 10 {
		t.Fatalf("len = %d, want cap 10", s.Len("t"))
	}
}
