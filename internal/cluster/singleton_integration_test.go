// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package cluster

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// TestPGSingletonTwoReplicaFailover runs two coordinators against the same
// real PostgreSQL advisory lock. It proves the standby does not duplicate
// side effects and takes over on its next retry after the holder exits.
func TestPGSingletonTwoReplicaFailover(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()

	const interval = 250 * time.Millisecond
	leaseName := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	firstLease, err := NewPGLease(pool, leaseName, "replica-a")
	if err != nil {
		t.Fatal(err)
	}
	secondLease, err := NewPGLease(pool, leaseName, "replica-b")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	first := newCoordinator(firstLease, interval, log)
	second := newCoordinator(secondLease, interval, log)

	var active, maxActive atomic.Int64
	starts := make(chan LeaseToken, 4)
	task := func(ctx context.Context, token LeaseToken) error {
		now := active.Add(1)
		for {
			old := maxActive.Load()
			if now <= old || maxActive.CompareAndSwap(old, now) {
				break
			}
		}
		starts <- token
		defer active.Add(-1)
		<-ctx.Done()
		return ctx.Err()
	}
	if err := first.Register("integration-side-effects", task); err != nil {
		t.Fatal(err)
	}
	if err := second.Register("integration-side-effects", task); err != nil {
		t.Fatal(err)
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneA <- first.Run(ctxA) }()
	go func() { doneB <- second.Run(ctxB) }()
	t.Cleanup(func() {
		cancelA()
		cancelB()
	})

	var initial LeaseToken
	select {
	case initial = <-starts:
	case <-time.After(5 * time.Second):
		t.Fatal("neither PostgreSQL-backed replica acquired the singleton lease")
	}
	time.Sleep(2 * interval)
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("PostgreSQL lease allowed duplicate work: max active=%d", got)
	}

	failedAt := time.Now()
	if initial.HolderID == "replica-a" {
		cancelA()
	} else {
		cancelB()
	}
	var failover LeaseToken
	select {
	case failover = <-starts:
	case <-time.After(4 * interval):
		t.Fatal("PostgreSQL standby did not acquire after holder shutdown")
	}
	// The standby retries once per interval. A second interval is allowed for
	// CI scheduler and database round-trip overhead around that retry boundary.
	if elapsed := time.Since(failedAt); elapsed > 2*interval {
		t.Fatalf("PostgreSQL singleton failover took %s, retry interval=%s", elapsed, interval)
	}
	if failover.HolderID == initial.HolderID || failover.Epoch <= initial.Epoch {
		t.Fatalf("failover token=%+v initial=%+v", failover, initial)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("old and new PostgreSQL epochs overlapped: max active=%d", got)
	}

	cancelA()
	cancelB()
	for name, done := range map[string]<-chan error{"replica-a": doneA, "replica-b": doneB} {
		select {
		case runErr := <-done:
			if runErr != nil {
				t.Fatalf("%s coordinator: %v", name, runErr)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s coordinator did not stop", name)
		}
	}
}
