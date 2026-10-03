// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"testing"
	"time"
)

// RTO-20: notification bookkeeping must survive a singleton-leader failover.
// Notification state (last-notified + firing-since) used to live ONLY in the
// leader's in-memory engine, so when the lease moved to another replica the
// fresh engine treated a still-firing alert as a brand-new firing and sent it
// AGAIN. These tests drive the REAL engine notify path and simulate failover
// with a fresh engine over the SAME persisted state (the engine half of the
// contract; the store half rides the integration suite, mirroring
// TestPersistedOpsRestoreSurvivesRestart).

// failoverFixture builds leaders that share one durable notification store (the
// alert_notifications table in prod) and one notification counter, so the count
// is "notifications delivered for ONE continuous firing across all leaders".
type failoverFixture struct {
	now       time.Time
	persisted map[string]NotifyState
	total     int
	src       *fakeSource
}

func newFailoverFixture() *failoverFixture {
	return &failoverFixture{
		now:       time.Unix(1_700_000_000, 0).UTC(),
		persisted: map[string]NotifyState{},
		src:       &fakeSource{samples: []Sample{sample(250, map[string]string{"target": "db", "tenant_id": "t-a"})}},
	}
}

// leader builds a fresh engine over the shared store + clock + counter, wired
// exactly as the control plane wires it (SetNotifyHook persists on delivery).
// The counter tracks FIRING notifications only — the quantity RTO-20 is about —
// so a recovery ("resolved") delivery is not mistaken for a re-notify.
func (f *failoverFixture) leader() *Engine {
	en := NewEngine(f.src, nil, discard(), WithAlertSink(func(_ context.Context, a Alert) {
		if a.State == StateFiring {
			f.total++
		}
	}))
	en.clock = func() time.Time { return f.now }
	en.SetNotifyHook(func(key string, ns NotifyState) { f.persisted[key] = ns })
	return en
}

// TestNotifyOnceSurvivesFailover: a renotify=0 ("notify once") alert that keeps
// firing across a leader failover is delivered exactly once, not twice.
func TestNotifyOnceSurvivesFailover(t *testing.T) {
	f := newFailoverFixture()
	rule := thresholdRule()
	rule.ForN = 1
	rule.RenotifySeconds = 0 // notify once

	// Leader A fires the alert and delivers the single notification.
	a := f.leader()
	if _, err := a.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if f.total != 1 {
		t.Fatalf("leader A should notify once: total=%d, want 1", f.total)
	}
	if len(f.persisted) != 1 {
		t.Fatalf("the notify hook must persist notification state: have %d rows, want 1", len(f.persisted))
	}

	// Failover: leader A is killed; the alert keeps firing. A FRESH leader B
	// takes the lease and rehydrates the persisted notification state.
	f.now = f.now.Add(45 * time.Second)
	b := f.leader()
	b.RestoreNotifications(f.persisted)

	// Leader B evaluates the SAME still-firing series. It must NOT re-notify.
	if _, err := b.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if f.total != 1 {
		t.Fatalf("RTO-20: a continuously-firing notify-once alert was re-sent after failover: total=%d, want 1", f.total)
	}
}

// TestRenotifyCadencePreservedAcrossFailover: a renotify>0 alert resumes its
// cadence relative to the PERSISTED last-notified after failover — the next
// notify is due per that timestamp, not immediately and not reset to now.
func TestRenotifyCadencePreservedAcrossFailover(t *testing.T) {
	f := newFailoverFixture()
	rule := thresholdRule()
	rule.ForN = 1
	rule.RenotifySeconds = 300 // renotify every 5 minutes

	// Leader A fires once at t0.
	a := f.leader()
	if _, err := a.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if f.total != 1 {
		t.Fatalf("leader A first fire: total=%d, want 1", f.total)
	}

	// Failover 60s later — the 300s cadence has NOT elapsed.
	f.now = f.now.Add(60 * time.Second)
	b := f.leader()
	b.RestoreNotifications(f.persisted)

	// Still firing, only 60s since the persisted last-notified: no renotify.
	if _, err := b.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if f.total != 1 {
		t.Fatalf("RTO-20: renotify cadence was reset by failover (re-sent too early): total=%d, want 1", f.total)
	}

	// Advance past the cadence measured from the ORIGINAL notify (t0+300s).
	f.now = f.now.Add(241 * time.Second) // t0 + 301s
	if _, err := b.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if f.total != 2 {
		t.Fatalf("renotify should fire once the persisted cadence elapses: total=%d, want 2", f.total)
	}
}

// TestResolveClearsPersistedNotificationState: when a firing episode resolves,
// the engine clears its in-memory notification bookkeeping so a FUTURE episode
// of the same series notifies afresh (the control plane deletes the durable row
// in the same resolve hook). This guards the reset that makes the notify-once
// decision key off last-notified instead of firstFiring.
func TestResolveClearsPersistedNotificationState(t *testing.T) {
	f := newFailoverFixture()
	rule := thresholdRule()
	rule.ForN = 1
	rule.RenotifySeconds = 0

	en := f.leader()
	// Fire (notify 1).
	if _, err := en.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	// Resolve.
	f.src.samples = []Sample{sample(0, map[string]string{"target": "db", "tenant_id": "t-a"})}
	f.now = f.now.Add(time.Minute)
	if _, err := en.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	// Fire a NEW episode: it must notify again (notify 2), proving resolve reset
	// the last-notified rather than leaving it to suppress the new episode.
	f.src.samples = []Sample{sample(250, map[string]string{"target": "db", "tenant_id": "t-a"})}
	f.now = f.now.Add(time.Minute)
	if _, err := en.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if f.total != 2 {
		t.Fatalf("a new firing episode after resolve must notify afresh: total=%d, want 2", f.total)
	}
}
