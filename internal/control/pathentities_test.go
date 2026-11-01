// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

func TestCurrentPathUsesDiscoveryStartNotBatchFlushTime(t *testing.T) {
	ctx := context.Background()
	batched := pathstore.NewBatchingSaver(pathstore.NewMemory(),
		slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour, 100)
	t.Cleanup(func() { _ = batched.Close() })
	p := &path.Path{Target: "10.42.0.1", Hops: []path.Hop{{TTL: 1,
		Nodes: []path.HopNode{{IP: "10.42.0.254"}}}}}
	assignedAt := time.Now().UTC().Add(-30 * time.Minute)
	binding := store.PathTestBinding{Target: p.Target, AssignedAt: assignedAt}
	oldTraceStartedAt := assignedAt.Add(-30 * time.Minute)
	// An old trace can be enqueued and flushed after an assignment. Its start
	// time must still keep the new context unavailable.
	if err := batched.Save(pathstore.WithDiscoveryStartedAt(ctx, oldTraceStartedAt), "tenant-a", p); err != nil {
		t.Fatal(err)
	}
	if got, found, err := latestPathAfterBinding(ctx, batched,
		"tenant-a", binding); err != nil || found || got != nil {
		t.Fatalf("pre-binding queued round inherited context: found=%v err=%v path=%+v", found, err, got)
	}
	if err := batched.Save(pathstore.WithDiscoveryStartedAt(ctx, time.Now().UTC()), "tenant-a", p); err != nil {
		t.Fatal(err)
	}
	if got, found, err := latestPathAfterBinding(ctx, batched,
		"tenant-a", binding); err != nil || !found || got == nil ||
		len(got.Hops) != 1 {
		t.Fatalf("fresh post-binding round missing: found=%v err=%v path=%+v", found, err, got)
	}
}
