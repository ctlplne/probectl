// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// countingFence records how many fenced transactions a store opened and
// whether it lets writes through.
type countingFence struct {
	calls  int
	refuse bool
}

func (f *countingFence) WithTenantWrites(ctx context.Context, _ []string, write func(context.Context) error) error {
	f.calls++
	if f.refuse {
		return errors.New("tenant writes are fenced")
	}
	return write(ctx)
}

// TestBatchTakesTheFenceOncePerBatch (DPR-106): a flush of the eBPF service
// map carries hundreds of edges; observing each under its own fence cost the
// lab's topology consumer seconds per record. A batch must cost one fence
// round trip, land every observation, and still drop the whole batch loudly
// when the tenant is fenced.
func TestBatchTakesTheFenceOncePerBatch(t *testing.T) {
	fence := &countingFence{}
	store := WithTenantWriteFence(NewMemoryStore(), fence)
	ts, err := store.ForTenant("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	edge := func(i int) ServiceEdgeInput {
		return ServiceEdgeInput{Source: fmt.Sprintf("svc-%d", i), Destination: "db", DestPort: 5432}
	}

	// Per-edge: one fenced transaction per observation (the old cost).
	for i := 0; i < 20; i++ {
		ts.ObserveServiceEdge(edge(i), at)
	}
	if fence.calls != 20 {
		t.Fatalf("per-edge observations cost one fence each, got %d", fence.calls)
	}

	// Batched: one fenced transaction for all of them.
	fence.calls = 0
	ObserveBatched(ts, func(g TenantStore) {
		for i := 20; i < 220; i++ {
			g.ObserveServiceEdge(edge(i), at)
		}
	})
	if fence.calls != 1 {
		t.Fatalf("a batch must take the fence once, got %d", fence.calls)
	}
	if n := len(ts.Latest().Edges); n < 220 {
		t.Fatalf("every batched observation must land, got %d edges", n)
	}

	// A fenced tenant drops the whole batch, nothing partial.
	fence.refuse = true
	before := len(ts.Latest().Edges)
	ObserveBatched(ts, func(g TenantStore) {
		for i := 300; i < 310; i++ {
			g.ObserveServiceEdge(edge(i), at)
		}
	})
	if got := len(ts.Latest().Edges); got != before {
		t.Fatalf("a refused fence must drop the batch, edges %d -> %d", before, got)
	}

	// An unfenced store applies the batch directly.
	plain, _ := NewMemoryStore().ForTenant("22222222-2222-4222-8222-222222222222")
	ObserveBatched(plain, func(g TenantStore) { g.ObserveServiceEdge(edge(1), at) })
	if len(plain.Latest().Edges) != 1 {
		t.Fatal("an unfenced store must apply the batch directly")
	}
}
