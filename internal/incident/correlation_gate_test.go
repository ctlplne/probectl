// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package incident

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
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
	inc := store.get(open[0].ID)
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

// TestCrossPlaneCorrelationGateRefusesKeylessPlane extends the gate with the
// case it could not previously see (S-9d415bb9): a synthetic NEW plane that
// emits signals carrying neither Target nor Prefix.
//
// Relatedness is a target/prefix join, so such a signal can never correlate
// with anything — before this it was accepted and silently produced ONE
// INCIDENT PER SIGNAL, fragmenting the cross-plane invariant that is the
// product's headline differentiator, while the gate only ever exercised planes
// that already set a target. The boundary now refuses it and names the plane,
// so a new plane fails at its first emission rather than quietly degrading
// correlation for everyone.
func TestCrossPlaneCorrelationGateRefusesKeylessPlane(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, 10*time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Now()

	inc, err := c.Ingest(context.Background(), Signal{
		TenantID: "t-a", Plane: "synthetic-new-plane", Kind: "widget.degraded",
		Severity: SeverityWarning, OccurredAt: now,
	})
	if err == nil {
		t.Fatal("a signal with neither Target nor Prefix must be REFUSED: it can never correlate and would open one incident per signal")
	}
	if !errors.Is(err, ErrNoCorrelationKey) {
		t.Fatalf("refusal must be the correlation-key sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "synthetic-new-plane") {
		t.Fatalf("the refusal must NAME the offending plane so its author can fix it: %v", err)
	}
	if inc != nil {
		t.Fatal("a refused signal must not open an incident")
	}
	if got := store.Len(); got != 0 {
		t.Fatalf("a refused signal left %d incidents behind", got)
	}

	// The SAME plane correlates normally once it supplies a key — the rule is
	// "bring a correlation key", not "new planes are unwelcome".
	target := "203.0.113.77"
	first, err := c.Ingest(context.Background(), Signal{
		TenantID: "t-a", Plane: "synthetic-new-plane", Kind: "widget.degraded",
		Severity: SeverityWarning, Target: target, OccurredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Ingest(context.Background(), Signal{
		TenantID: "t-a", Plane: "network", Kind: "alert.firing",
		Severity: SeverityCritical, Target: target, OccurredAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("a keyed new plane must correlate cross-plane: %s vs %s", first.ID, second.ID)
	}
}

// TestSignalCorrelationKeyPrefersTargetThenPrefix pins the accessor planes use
// to self-check before emitting.
func TestSignalCorrelationKeyPrefersTargetThenPrefix(t *testing.T) {
	if got := (Signal{Target: "t", Prefix: "p"}).CorrelationKey(); got != "t" {
		t.Fatalf("CorrelationKey = %q, want the target", got)
	}
	if got := (Signal{Prefix: "203.0.113.0/24"}).CorrelationKey(); got != "203.0.113.0/24" {
		t.Fatalf("CorrelationKey = %q, want the prefix fallback", got)
	}
	if got := (Signal{}).CorrelationKey(); got != "" {
		t.Fatalf("a keyless signal must report no key, got %q", got)
	}
}
