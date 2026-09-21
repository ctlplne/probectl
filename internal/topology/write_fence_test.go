// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"context"
	"errors"
	"testing"
	"time"
)

type deadlineRecordingFence struct {
	deadlineSet bool
	remaining   time.Duration
}

func (f *deadlineRecordingFence) WithTenantWrites(
	ctx context.Context,
	_ []string,
	_ func(context.Context) error,
) error {
	deadline, ok := ctx.Deadline()
	f.deadlineSet = ok
	if ok {
		f.remaining = time.Until(deadline)
	}
	return errors.New("injected unavailable writer lease")
}

func TestTopologyWriteFenceBoundsLeaseWait(t *testing.T) {
	fence := &deadlineRecordingFence{}
	store := WithTenantWriteFence(NewMemoryStore(), fence)
	tenant, err := store.ForTenant("tenant-a")
	if err != nil {
		t.Fatal(err)
	}

	tenant.ObserveServiceEdge(
		ServiceEdgeInput{Source: "source", Destination: "destination"},
		time.Now().UTC(),
	)

	if !fence.deadlineSet {
		t.Fatal("topology writer fence received an unbounded context")
	}
	if fence.remaining <= 0 || fence.remaining > 10*time.Second {
		t.Fatalf("topology writer fence deadline remaining = %v, want a small positive bound", fence.remaining)
	}
	if got := tenant.Latest(); len(got.Nodes) != 0 || len(got.Edges) != 0 {
		t.Fatalf("failed topology writer lease mutated the graph: %+v", got)
	}
}
