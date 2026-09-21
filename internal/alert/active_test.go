// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// activeHarness drives a real engine with a controllable metric source + clock
// and a counting notifier sink.
type activeHarness struct {
	en     *Engine
	value  float64
	now    time.Time
	fired  int
	sinked int
}

type harnessSource struct{ h *activeHarness }

func (s harnessSource) Current(context.Context, string, map[string]string) ([]Sample, error) {
	return []Sample{{Labels: map[string]string{"target": "db", "tenant_id": "t-a"}, Value: s.h.value}}, nil
}

func newActiveHarness(t *testing.T) (*activeHarness, Rule) {
	t.Helper()
	h := &activeHarness{now: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h.en = NewEngine(harnessSource{h: h}, nil, log,
		WithAlertSink(func(context.Context, Alert) { h.sinked++ }))
	h.en.clock = func() time.Time { return h.now }
	rule := Rule{
		ID: "r1", TenantID: "t-a", Name: "rtt high", Enabled: true,
		Metric: "probectl_result_rtt_ms", Type: Threshold,
		Comparison: GT, Threshold: 100, Severity: SeverityCritical,
		RenotifySeconds: 60,
	}
	return h, rule
}

func (h *activeHarness) eval(t *testing.T, rule Rule) []Alert {
	t.Helper()
	acted, err := h.en.Evaluate(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	h.fired += len(acted)
	return acted
}

func TestActiveReflectsEngineTruth(t *testing.T) {
	h, rule := newActiveHarness(t)

	// Nothing firing yet.
	if got := h.en.Active(); len(got) != 0 {
		t.Fatalf("active before firing = %+v", got)
	}

	// Breach -> firing -> visible with full metadata.
	h.value = 250
	h.eval(t, rule)
	active := h.en.Active()
	if len(active) != 1 {
		t.Fatalf("active = %+v", active)
	}
	a := active[0]
	if a.RuleID != "r1" || a.RuleName != "rtt high" || a.Severity != SeverityCritical ||
		a.Metric != "probectl_result_rtt_ms" || a.Labels["target"] != "db" ||
		a.Value != 250 || a.Reason == "" || !a.Since.Equal(h.now) {
		t.Fatalf("active alert = %+v", a)
	}
	if a.SilencedUntil != nil || a.AckedBy != "" {
		t.Fatalf("fresh alert carries operator state: %+v", a)
	}

	// Recovery -> gone from the active list.
	h.value = 10
	h.now = h.now.Add(time.Minute)
	h.eval(t, rule)
	if got := h.en.Active(); len(got) != 0 {
		t.Fatalf("active after resolve = %+v", got)
	}
}

func TestSilenceSuppressesNotificationsNotState(t *testing.T) {
	h, rule := newActiveHarness(t)
	h.value = 250
	h.eval(t, rule)
	if h.sinked != 1 {
		t.Fatalf("sinked = %d", h.sinked)
	}
	fp := h.en.Active()[0].Fingerprint

	// Silence for 10 minutes.
	a, err := h.en.Silence(fp, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.SilencedUntil == nil || !a.SilencedUntil.Equal(h.now.Add(10*time.Minute)) {
		t.Fatalf("silenced_until = %+v", a.SilencedUntil)
	}

	// Renotify cadence passes (60s) but the silence holds: no new notification,
	// series still listed as firing + silenced.
	h.now = h.now.Add(2 * time.Minute)
	h.eval(t, rule)
	if h.sinked != 1 {
		t.Fatalf("silenced renotify leaked: sinked = %d", h.sinked)
	}
	if got := h.en.Active(); len(got) != 1 || got[0].SilencedUntil == nil {
		t.Fatalf("active during silence = %+v", got)
	}

	// Silence expires -> renotify resumes.
	h.now = h.now.Add(9 * time.Minute)
	h.eval(t, rule)
	if h.sinked != 2 {
		t.Fatalf("renotify after expiry: sinked = %d", h.sinked)
	}

	// Resolve clears the silence and notifies recovery.
	h.value = 10
	h.now = h.now.Add(time.Minute)
	acted := h.eval(t, rule)
	if len(acted) != 1 || acted[0].State != StateResolved {
		t.Fatalf("resolve = %+v", acted)
	}

	// Re-fire: a fresh episode carries no stale operator state.
	h.value = 300
	h.now = h.now.Add(time.Minute)
	h.eval(t, rule)
	if got := h.en.Active(); len(got) != 1 || got[0].SilencedUntil != nil || got[0].AckedBy != "" {
		t.Fatalf("stale operator state leaked into new episode: %+v", got)
	}
}

func TestAcknowledgeAndErrors(t *testing.T) {
	h, rule := newActiveHarness(t)
	h.value = 250
	h.eval(t, rule)
	fp := h.en.Active()[0].Fingerprint

	a, err := h.en.Acknowledge(fp, "sre@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if a.AckedBy != "sre@acme.example" || a.AckedAt == nil {
		t.Fatalf("ack = %+v", a)
	}
	// Ack does not suppress notifications (renotify still fires).
	h.now = h.now.Add(2 * time.Minute)
	h.eval(t, rule)
	if h.sinked != 2 {
		t.Fatalf("ack suppressed delivery: sinked = %d", h.sinked)
	}

	// Unknown fingerprint and non-firing series fail closed.
	if _, err := h.en.Silence("nope", time.Minute); !errors.Is(err, ErrNotActive) {
		t.Fatalf("silence unknown = %v", err)
	}
	if _, err := h.en.Acknowledge("nope", "x"); !errors.Is(err, ErrNotActive) {
		t.Fatalf("ack unknown = %v", err)
	}
	// Out-of-range silence durations rejected.
	if _, err := h.en.Silence(fp, -time.Minute); err == nil {
		t.Fatal("negative silence accepted")
	}
	if _, err := h.en.Silence(fp, MaxSilence+time.Hour); err == nil {
		t.Fatal("over-max silence accepted")
	}
	// Silence(0) clears.
	if _, err := h.en.Silence(fp, time.Hour); err != nil {
		t.Fatal(err)
	}
	a, err = h.en.Silence(fp, 0)
	if err != nil || a.SilencedUntil != nil {
		t.Fatalf("clear silence: %+v err=%v", a, err)
	}
}

// ARCH-005 (Sprint 16, the volatile-stores ADR's documented exception): a
// persisted silence/ack RESTORED into a FRESH engine re-applies the first
// time its series fires again — operator state survives a control-plane
// restart. This is the engine half of the restart-survival contract; the
// store half (alert_ops) rides the integration suite.
func TestPersistedOpsRestoreSurvivesRestart(t *testing.T) {
	// "Before the restart": fire + silence + ack, capture what the API layer
	// persists (fingerprint, deadline, acker).
	h1, rule := newActiveHarness(t)
	h1.value = 250
	h1.eval(t, rule)
	fp := h1.en.Active()[0].Fingerprint
	if _, err := h1.en.Silence(fp, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := h1.en.Acknowledge(fp, "oncall@example"); err != nil {
		t.Fatal(err)
	}
	silencedUntil := h1.now.Add(30 * time.Minute)

	// "After the restart": a FRESH engine restores the persisted ops; the
	// series fires again and arrives silenced + acked WITHOUT new operator
	// action — and the silence suppresses the notification.
	h2, rule2 := newActiveHarness(t)
	h2.en.RestoreOps(map[string]RestoredOp{
		fp: {SilencedUntil: silencedUntil, AckedBy: "oncall@example", AckedAt: h1.now},
	})
	h2.value = 250
	h2.eval(t, rule2)
	if h2.sinked != 0 {
		t.Fatalf("restored silence must suppress the firing notification, sinked=%d", h2.sinked)
	}
	act := h2.en.Active()
	if len(act) != 1 {
		t.Fatalf("active = %d, want 1 (silence suppresses notify, not state)", len(act))
	}
	if act[0].SilencedUntil == nil || act[0].AckedBy != "oncall@example" {
		t.Fatalf("restored op not applied: %+v", act[0])
	}

	// An EXPIRED restored silence is skipped (fires + notifies normally).
	h3, rule3 := newActiveHarness(t)
	h3.en.RestoreOps(map[string]RestoredOp{
		fp: {SilencedUntil: h3.now.Add(-time.Minute)},
	})
	h3.value = 250
	h3.eval(t, rule3)
	if h3.sinked != 1 {
		t.Fatalf("expired restored silence must not suppress: sinked=%d", h3.sinked)
	}

	// Resolve fires the cleanup hook (the API layer deletes the row).
	resolved := make(chan string, 1)
	h2.en.SetResolveHook(func(f string) { resolved <- f })
	h2.value = 0 // recovers
	h2.eval(t, rule2)
	select {
	case got := <-resolved:
		if got != fp {
			t.Fatalf("resolve hook fingerprint = %q, want %q", got, fp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolve hook never fired (persisted row would leak)")
	}
}

// DPR-067: operator state persisted by another control replica reaches the
// evaluator through ApplyOps on its next pass — a silence lands, a lifted
// silence clears, an acknowledgment sticks — and a maintenance window created
// elsewhere becomes the engine's window.
func TestApplyOpsReconcilesPersistedOperatorState(t *testing.T) {
	h, rule := newActiveHarness(t)
	h.value = 250
	h.eval(t, rule)
	fp := h.en.Active()[0].Fingerprint

	until := h.now.Add(30 * time.Minute)
	h.en.ApplyOps(map[string]RestoredOp{fp: {SilencedUntil: until, AckedBy: "oncall@acme.example", AckedAt: h.now}})
	a := h.en.Active()[0]
	if a.SilencedUntil == nil || !a.SilencedUntil.Equal(until) || a.AckedBy != "oncall@acme.example" {
		t.Fatalf("persisted ops not applied: %+v", a)
	}
	h.en.ApplyOps(map[string]RestoredOp{fp: {AckedBy: "oncall@acme.example", AckedAt: h.now}})
	if a := h.en.Active()[0]; a.SilencedUntil != nil || a.AckedBy == "" {
		t.Fatalf("lifted silence must clear and the ack must stick: %+v", a)
	}

	w := MaintenanceWindow{ID: "w1", Name: "db rollout", StartsAt: h.now, EndsAt: h.now.Add(time.Hour), RuleIDs: []string{rule.ID}}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	h.en.ReplaceMaintenanceWindows([]MaintenanceWindow{w})
	if got := h.en.MaintenanceWindows(); len(got) != 1 || got[0].ID != "w1" {
		t.Fatalf("maintenance windows = %+v", got)
	}
	if prev := h.en.PreviewMaintenance(rule, nil, h.now, h.now.Add(2*time.Hour)); len(prev) != 1 || prev[0].WindowID != "w1" {
		t.Fatalf("preview = %+v", prev)
	}
	h.en.ReplaceMaintenanceWindows(nil)
	if got := h.en.MaintenanceWindows(); len(got) != 0 {
		t.Fatalf("windows not replaced: %+v", got)
	}
}
