// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/path"
)

// CORRECT-010: a path save mints a fresh path_id + now() per call on a plain
// MergeTree, so an at-least-once redelivered discovery is stored as a second
// snapshot. That is BENIGN because the only read, Latest(), returns the single
// most-recent snapshot for a target — a redelivered duplicate is never
// double-counted or double-rendered. This pins that contract: re-saving an
// identical discovery still yields ONE coherent snapshot on read.
func TestLatestReturnsOneSnapshotAfterResave(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	p := samplePath()
	// At-least-once: the same discovery delivered twice.
	if err := m.Save(ctx, "t1", p); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(ctx, "t1", p); err != nil {
		t.Fatal(err)
	}

	got, ok, err := m.Latest(ctx, "t1", p.Target)
	if err != nil || !ok {
		t.Fatalf("Latest: ok=%v err=%v", ok, err)
	}
	// Latest is a SINGLE snapshot — the duplicate does not double its hops.
	if len(got.Hops) != len(p.Hops) {
		t.Fatalf("Latest returned %d hops, want %d — a redelivered save was double-counted", len(got.Hops), len(p.Hops))
	}
	if len(got.Links) != len(p.Links) {
		t.Fatalf("Latest returned %d links, want %d", len(got.Links), len(p.Links))
	}
	// The hop fan-out is unchanged (no merged/duplicated nodes).
	for i := range got.Hops {
		if len(got.Hops[i].Nodes) != len(p.Hops[i].Nodes) {
			t.Fatalf("hop %d node count changed: got %d, want %d", i, len(got.Hops[i].Nodes), len(p.Hops[i].Nodes))
		}
	}
	_ = path.Path{} // keep the path import meaningful if Hops shape changes
}
