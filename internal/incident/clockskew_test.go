// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// CORRECT-009: a signal's OccurredAt is sourced from independent planes whose
// clocks may drift. Before the fix only a ZERO OccurredAt was filled with now();
// a far-future OccurredAt was trusted verbatim and pushed the incident's
// LastSeenAt (and thus its correlation window) arbitrarily into the future,
// keeping the incident "live" forever. The fix clamps a future-dated OccurredAt
// to ingest time.
func TestFutureOccurredAtIsClampedNotWindowExtending(t *testing.T) {
	fixed := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewCorrelator(NewMemoryStore(), DefaultWindow, log).withClock(func() time.Time { return fixed })
	ctx := context.Background()

	// A signal stamped 1h in the future (clock skew).
	inc, err := c.Ingest(ctx, Signal{
		TenantID: "t1", Plane: "threat", Kind: "ndr.beacon", Severity: SeverityWarning,
		Title: "beacon", Target: "10.0.0.5", OccurredAt: fixed.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// The incident's LastSeenAt must be clamped to ingest time, not 1h ahead —
	// otherwise the window would stay open far into the future.
	if inc.LastSeenAt.After(fixed.Add(MaxFutureSkew)) {
		t.Fatalf("LastSeenAt = %s extends the window past the skew bound (clamp to ~%s expected)", inc.LastSeenAt, fixed)
	}
	if inc.StartedAt.After(fixed.Add(MaxFutureSkew)) {
		t.Fatalf("StartedAt = %s was not clamped", inc.StartedAt)
	}

	// A small benign skew (1m, under the bound) passes through untouched.
	c2 := NewCorrelator(NewMemoryStore(), DefaultWindow, log).withClock(func() time.Time { return fixed })
	near := fixed.Add(time.Minute)
	inc2, err := c2.Ingest(ctx, Signal{
		TenantID: "t1", Plane: "bgp", Kind: "bgp.hijack", Severity: SeverityCritical,
		Title: "hijack", Prefix: "203.0.113.0/24", OccurredAt: near,
	})
	if err != nil {
		t.Fatalf("ingest near: %v", err)
	}
	if !inc2.LastSeenAt.Equal(near) {
		t.Fatalf("benign sub-bound skew was altered: LastSeenAt=%s, want %s", inc2.LastSeenAt, near)
	}
}
