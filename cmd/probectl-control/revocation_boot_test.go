// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// fakeRevocationLister fails its first failN calls, then returns serials/ids.
type fakeRevocationLister struct {
	failN   int
	calls   int
	serials []string
	ids     []string
	err     error
}

func (f *fakeRevocationLister) ListRevoked(context.Context) ([]string, []string, error) {
	f.calls++
	if f.calls <= f.failN {
		return nil, nil, f.err
	}
	return f.serials, f.ids, nil
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestLoadInitialRevocationFailsClosed proves AUTHZ-26 / G7-4: when the
// persisted revocation state cannot be read at boot, the mandatory first load
// returns an error (so the caller refuses to start the agent listener) and
// never applies a deny-list. A fail-open implementation (returning nil here)
// would serve the agent listener with an empty deny-list and accept a revoked
// agent — exactly the regression this guards.
func TestLoadInitialRevocationFailsClosed(t *testing.T) {
	applied := false
	l := &fakeRevocationLister{failN: 100, err: errors.New("revocation store unavailable")}
	err := loadInitialRevocation(context.Background(), l, func([]string, []string) { applied = true }, 3, time.Millisecond, discardLogger())
	if err == nil {
		t.Fatal("initial revocation load must fail closed when ListRevoked keeps failing, got nil error")
	}
	if applied {
		t.Fatal("a deny-list must never be applied when the mandatory load failed")
	}
	if l.calls != 3 {
		t.Fatalf("attempts = %d, want 3 (bounded retry)", l.calls)
	}
}

// TestLoadInitialRevocationRetriesThenApplies proves the retry path: a couple of
// transient failures are tolerated, and once the load succeeds the revoked
// serials/IDs are applied to the deny-list (non-vacuous: it does load on
// success, not merely always error).
func TestLoadInitialRevocationRetriesThenApplies(t *testing.T) {
	var gotSerials, gotIDs []string
	l := &fakeRevocationLister{
		failN: 2, err: errors.New("transient blip"),
		serials: []string{"serial-A"}, ids: []string{"spiffe://probectl/agent/x"},
	}
	err := loadInitialRevocation(context.Background(), l, func(s, ids []string) { gotSerials, gotIDs = s, ids }, 5, time.Millisecond, discardLogger())
	if err != nil {
		t.Fatalf("load should succeed after transient failures, got: %v", err)
	}
	if len(gotSerials) != 1 || gotSerials[0] != "serial-A" || len(gotIDs) != 1 {
		t.Fatalf("applied serials/ids = %v / %v, want [serial-A] and one id", gotSerials, gotIDs)
	}
	if l.calls != 3 {
		t.Fatalf("calls = %d, want 3 (2 failures then success)", l.calls)
	}
}

// TestLoadInitialRevocationHonorsContextCancel proves the retry loop exits
// promptly on context cancellation rather than spinning through every attempt.
func TestLoadInitialRevocationHonorsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := &fakeRevocationLister{failN: 100, err: errors.New("down")}
	if err := loadInitialRevocation(ctx, l, func([]string, []string) {}, 10, time.Hour, discardLogger()); err == nil {
		t.Fatal("expected an error when the context is canceled mid-retry")
	}
	if l.calls > 1 {
		t.Fatalf("calls = %d, want 1 before honoring cancellation", l.calls)
	}
}
