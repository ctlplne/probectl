// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tsdb

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type leaseTrackingFence struct {
	held     atomic.Bool
	acquired chan struct{}
	released chan struct{}
	once     sync.Once
}

func (f *leaseTrackingFence) WithTenantWrites(
	ctx context.Context,
	_ []string,
	write func(context.Context) error,
) error {
	f.held.Store(true)
	f.once.Do(func() { close(f.acquired) })
	err := write(ctx)
	f.held.Store(false)
	close(f.released)
	return err
}

type leaseObservingWriter struct {
	fence     *leaseTrackingFence
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
	wroteHeld atomic.Bool
}

func (w *leaseObservingWriter) Write(_ context.Context, _ []Series) error {
	w.once.Do(func() { close(w.started) })
	<-w.release
	w.wroteHeld.Store(w.fence.held.Load())
	return nil
}

func (w *leaseObservingWriter) Close() error { return nil }

func TestBatchingWriteFenceSurvivesCallerCancellation(t *testing.T) {
	fence := &leaseTrackingFence{
		acquired: make(chan struct{}),
		released: make(chan struct{}),
	}
	inner := &leaseObservingWriter{
		fence:   fence,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseInner := func() { releaseOnce.Do(func() { close(inner.release) }) }
	t.Cleanup(releaseInner)

	writer := WithTenantWriteFence(
		NewBatchingWriter(inner, 2, 10*time.Millisecond),
		fence,
	)
	t.Cleanup(func() { _ = writer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- writer.Write(ctx, []Series{tenantSeries("fenced-cancel")})
	}()

	select {
	case <-fence.acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("tenant writer lease was not acquired")
	}
	select {
	case <-inner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("background TSDB flush did not reach the backend")
	}

	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled batch Write error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled batch Write did not return after its bounded grace")
	}

	select {
	case <-fence.released:
		t.Fatal("tenant writer lease released while the background TSDB mutation was still in flight")
	default:
	}

	releaseInner()
	select {
	case <-fence.released:
	case <-time.After(2 * time.Second):
		t.Fatal("tenant writer lease was not released after the backend mutation completed")
	}
	if !inner.wroteHeld.Load() {
		t.Fatal("TSDB backend mutation completed without the tenant writer lease held")
	}
}
