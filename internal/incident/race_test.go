// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// CORRECT-013: concurrent related signals for ONE tenant must collapse into a
// single incident. Before the per-tenant lock, two goroutines could both see
// "no open incident" and both Create, splitting one event across duplicates.
// Run many concurrent related signals and assert exactly one incident exists.
func TestConcurrentIngestOpensOneIncident(t *testing.T) {
	store := NewMemoryStore()
	c := NewCorrelator(store, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))

	now := time.Now()
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct samples: byte-identical deliveries are ONE signal since
			// DPR-078, and this test is about the read-then-create race.
			_, err := c.Ingest(context.Background(), Signal{
				TenantID: "t-a", Plane: "threat", Kind: "ndr.beacon",
				Severity: SeverityWarning, Target: "10.0.0.9", OccurredAt: now,
				Attributes: map[string]string{"sample": fmt.Sprint(i)},
			})
			if err != nil {
				t.Errorf("ingest: %v", err)
			}
		}(i)
	}
	wg.Wait()

	open, err := store.OpenIncidents(context.Background(), "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("concurrent related signals opened %d incidents, want exactly 1 (read-then-create race)", len(open))
	}
	if open[0].SignalCount != n {
		t.Fatalf("incident has %d signals, want all %d correlated into it", open[0].SignalCount, n)
	}
}
