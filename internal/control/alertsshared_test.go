// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/store"
)

type fakeSharedAlertStore struct {
	active      []alert.ActiveAlert
	evaluatedAt time.Time
	interval    time.Duration
	published   bool
	ops         map[string]store.AlertOp
	windows     map[string]alert.MaintenanceWindow
	tenants     map[string]bool
}

func (f *fakeSharedAlertStore) seen(tenant string) {
	if f.tenants == nil {
		f.tenants = map[string]bool{}
	}
	f.tenants[tenant] = true
}
func (f *fakeSharedAlertStore) ListActive(_ context.Context, tenant string) ([]alert.ActiveAlert, error) {
	f.seen(tenant)
	return append([]alert.ActiveAlert(nil), f.active...), nil
}
func (f *fakeSharedAlertStore) Status(_ context.Context, tenant string) (time.Time, time.Duration, bool, error) {
	f.seen(tenant)
	return f.evaluatedAt, f.interval, f.published, nil
}
func (f *fakeSharedAlertStore) ListOps(_ context.Context, _ string) ([]store.AlertOp, error) {
	out := make([]store.AlertOp, 0, len(f.ops))
	for _, op := range f.ops {
		out = append(out, op)
	}
	return out, nil
}
func (f *fakeSharedAlertStore) UpsertOp(_ context.Context, _ string, op store.AlertOp) error {
	if f.ops == nil {
		f.ops = map[string]store.AlertOp{}
	}
	f.ops[op.Fingerprint] = op
	return nil
}
func (f *fakeSharedAlertStore) DeleteOp(_ context.Context, _ string, fp string) error {
	delete(f.ops, fp)
	return nil
}
func (f *fakeSharedAlertStore) ListMaintenance(_ context.Context, _ string) ([]alert.MaintenanceWindow, error) {
	out := make([]alert.MaintenanceWindow, 0, len(f.windows))
	for _, w := range f.windows {
		out = append(out, w)
	}
	return out, nil
}
func (f *fakeSharedAlertStore) UpsertMaintenance(_ context.Context, _ string, w alert.MaintenanceWindow) error {
	if f.windows == nil {
		f.windows = map[string]alert.MaintenanceWindow{}
	}
	f.windows[w.ID] = w
	return nil
}
func (f *fakeSharedAlertStore) DeleteMaintenance(_ context.Context, _ string, id string) error {
	delete(f.windows, id)
	return nil
}

// TestPersistedAlertStateServesSharedStateOnAnyReplica (DPR-067): a replica
// without the evaluator used to answer "not running for this tenant"; it now
// serves the published active set with the persisted operator state overlaid,
// writes acknowledgements and silences to the shared ops, and reports the
// evaluator running from the leader's heartbeat.
func TestPersistedAlertStateServesSharedStateOnAnyReplica(t *testing.T) {
	now := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	f := &fakeSharedAlertStore{
		active:      []alert.ActiveAlert{{Fingerprint: "fp1", RuleID: "r1", RuleName: "checkout-down", Severity: alert.SeverityCritical, Since: now.Add(-time.Minute)}},
		evaluatedAt: now.Add(-20 * time.Second), interval: 30 * time.Second, published: true,
	}
	p := newPersistedAlertState(f, "t1", nil)
	p.now = func() time.Time { return now }

	if !p.Running() {
		t.Fatal("a heartbeat 20 s old must count as running")
	}
	if got := p.Active(); len(got) != 1 || got[0].Fingerprint != "fp1" || got[0].AckedBy != "" {
		t.Fatalf("active = %+v", got)
	}
	a, err := p.Acknowledge("fp1", "oncall@acme.example")
	if err != nil || a.AckedBy != "oncall@acme.example" || a.AckedAt == nil {
		t.Fatalf("ack = %+v err=%v", a, err)
	}
	if op := f.ops["fp1"]; op.AckedBy != "oncall@acme.example" || op.RuleID != "r1" {
		t.Fatalf("ack not persisted for the evaluator: %+v", op)
	}
	a, err = p.Silence("fp1", 10*time.Minute)
	if err != nil || a.SilencedUntil == nil || !a.SilencedUntil.Equal(now.Add(10*time.Minute)) || a.AckedBy == "" {
		t.Fatalf("silence = %+v err=%v", a, err)
	}
	if got := p.Active()[0]; got.SilencedUntil == nil || got.AckedBy == "" {
		t.Fatalf("overlay lost on read: %+v", got)
	}
	if _, err := p.Silence("nope", time.Minute); !errors.Is(err, alert.ErrNotActive) {
		t.Fatalf("unknown fingerprint = %v, want ErrNotActive", err)
	}
	if _, err := p.Silence("fp1", alert.MaxSilence+time.Second); err == nil {
		t.Fatal("silence beyond the maximum must be refused")
	}
	if a, err = p.Silence("fp1", 0); err != nil || a.SilencedUntil != nil {
		t.Fatalf("lifted silence = %+v err=%v", a, err)
	}
	if f.ops["fp1"].SilencedUntil != nil || f.ops["fp1"].AckedBy == "" {
		t.Fatalf("lifting a silence must keep the ack: %+v", f.ops["fp1"])
	}

	w, err := p.UpsertMaintenanceWindow(alert.MaintenanceWindow{Name: "db rollout", StartsAt: now, EndsAt: now.Add(time.Hour), RuleIDs: []string{"r1"}})
	if err != nil || w.ID == "" || f.windows[w.ID].Name != "db rollout" {
		t.Fatalf("maintenance upsert = %+v err=%v", w, err)
	}
	if prev := p.PreviewMaintenance(alert.Rule{ID: "r1"}, nil, now, now.Add(2*time.Hour)); len(prev) != 1 {
		t.Fatalf("preview = %+v", prev)
	}
	if !p.DeleteMaintenanceWindow(w.ID) || len(f.windows) != 0 {
		t.Fatal("maintenance delete failed")
	}

	f.evaluatedAt = now.Add(-5 * time.Minute)
	if p.Running() {
		t.Fatal("a stale heartbeat must not report running")
	}
	f.published = false
	if p.Running() || alertStateRunning(p) {
		t.Fatal("no heartbeat must not report running")
	}
	if !alertStateRunning(struct{ AlertStateSource }{}) || alertStateRunning(nil) {
		t.Fatal("engine-backed sources count as running; nil never does")
	}
}
