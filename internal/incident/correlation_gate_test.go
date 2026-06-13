// SPDX-License-Identifier: LicenseRef-probectl-TBD

package incident

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TEST-005 / CLAUDE.md §8 standing gate #2 — cross-plane correlation. Inject a
// multi-plane fault for ONE tenant/target (a threat detection AND a BGP event)
// and assert it surfaces as exactly ONE incident, tenant-scoped, carrying
// evidence from ≥2 distinct planes. A regression that splits cross-plane
// evidence into separate incidents (or correlates across tenants) fails here.
//
// This is the unit-level gate over the correlator and runs in verify-all. The
// full fault-injection e2e over a real bus + stores — injecting a multi-plane
// fault through real Kafka into the RLS-backed Postgres correlator and asserting
// ONE tenant-scoped incident — is TestCrossPlaneCorrelationE2E in
// internal/control (build tag integration; wired into the CI integration job,
// EXC-GATE-05). This unit gate stays the fast every-pass guard.
func TestCrossPlaneCorrelationGate(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, 10*time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Now()
	target := "203.0.113.10"

	// Plane 1: a threat detection against the target.
	if _, err := c.Ingest(context.Background(), Signal{
		TenantID: "t-a", Plane: "threat", Kind: "ndr.exfil",
		Severity: SeverityWarning, Target: target, OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Plane 2: a BGP event touching the same target, in-window.
	if _, err := c.Ingest(context.Background(), Signal{
		TenantID: "t-a", Plane: "bgp", Kind: "bgp.possible_hijack",
		Severity: SeverityCritical, Target: target, OccurredAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	// A DIFFERENT tenant's signal for the same target must NOT join (isolation).
	if _, err := c.Ingest(context.Background(), Signal{
		TenantID: "t-other", Plane: "threat", Kind: "ndr.exfil",
		Severity: SeverityWarning, Target: target, OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	open, err := store.OpenIncidents(context.Background(), "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("cross-plane fault produced %d incidents for t-a, want exactly 1", len(open))
	}
	inc := store.Get(open[0].ID)
	planes := map[string]bool{}
	for _, s := range inc.Signals {
		planes[s.Plane] = true
	}
	if len(planes) < 2 {
		t.Fatalf("incident carries %d planes of evidence, want >=2 (cross-plane correlation): %v", len(planes), planes)
	}
	// Severity rolls up to the worst plane's.
	if inc.Severity != SeverityCritical {
		t.Fatalf("incident severity = %s, want critical (max across planes)", inc.Severity)
	}
	// Isolation: the other tenant got its OWN separate incident.
	if other, _ := store.OpenIncidents(context.Background(), "t-other"); len(other) != 1 {
		t.Fatalf("t-other should have its own 1 incident, got %d", len(other))
	}
}
