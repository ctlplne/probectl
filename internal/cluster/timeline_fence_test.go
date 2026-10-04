// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cluster

import (
	"context"
	"testing"
)

// PLAT-19: an AUTOMATIC Postgres failover advances the WAL timeline with no
// cluster_promote() step, so the promotion epoch is NOT bumped. The fence must
// still mark an ex-primary on a superseded timeline stale (and fence its pool),
// not keep it writable — otherwise a writer endpoint still pointing at the old
// node accepts split-brain writes that are later lost.
func TestAutomaticTimelinePromotionFencesStalePrimary(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1, Timeline: 1, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1, Timeline: 1, WriterRegion: "us-east"}}
	fencer := &fakeFencer{}
	m := NewManager(topo(), writer, reader).WithWriteFencer(fencer)

	m.Refresh(ctx)
	if ok, reason := m.WriterUsable(); !ok {
		t.Fatalf("healthy primary must be usable: %s", reason)
	}

	// The standby followed the TRUE primary onto a new WAL timeline (automatic
	// failover) — timeline advances, epoch unchanged (no cluster_promote run).
	reader.set(Probe{InRecovery: true, Epoch: 1, Timeline: 2, WriterRegion: "us-east"})
	m.Refresh(ctx)

	if ok, reason := m.WriterUsable(); ok {
		t.Fatalf("ex-primary on a superseded WAL timeline must be fenced even with an unchanged epoch; got usable (reason=%q)", reason)
	}
	if role := m.Status().Writer.Role; role != RoleStale {
		t.Fatalf("writer must be RoleStale on the old timeline, got %v", role)
	}
	if !fencer.on {
		t.Fatal("the writer pool must be fenced read-only for a timeline-stale ex-primary")
	}
}

// A primary that has itself advanced onto the new timeline (it IS the promoted
// node) stays writable — the timeline fence must not fence the true primary.
func TestTimelineFenceReleasesOnThePromotedPrimary(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1, Timeline: 1}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1, Timeline: 1}}
	m := NewManager(topo(), writer, reader)
	m.Refresh(ctx)

	// Writer endpoint re-points to the promoted node: it is a primary on the new
	// timeline, and the reader follows it.
	writer.set(Probe{InRecovery: false, Epoch: 1, Timeline: 2})
	reader.set(Probe{InRecovery: true, Epoch: 1, Timeline: 2})
	m.Refresh(ctx)
	if ok, reason := m.WriterUsable(); !ok {
		t.Fatalf("the promoted primary on the new timeline must be usable: %s", reason)
	}
}
