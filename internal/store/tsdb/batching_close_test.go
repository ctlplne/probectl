// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tsdb

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type deadlineCheckingTSDBWriter struct {
	sawDeadline atomic.Bool
}

func (w *deadlineCheckingTSDBWriter) Write(ctx context.Context, _ []Series) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("TSDB batch backend context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > tsdbBackgroundFlushTimeout {
		return errors.New("TSDB batch backend deadline is outside the internal flush bound")
	}
	w.sawDeadline.Store(true)
	return nil
}

func (*deadlineCheckingTSDBWriter) Close() error { return nil }

func TestBatchingWriterBackgroundFlushHasDeadline(t *testing.T) {
	under := &deadlineCheckingTSDBWriter{}
	batching := NewBatchingWriter(under, 1, time.Hour)
	if err := batching.Write(
		context.Background(),
		[]Series{tenantSeries("probe_up")},
	); err != nil {
		t.Fatalf("size-triggered batch flush: %v", err)
	}
	if !under.sawDeadline.Load() {
		t.Fatal("size-triggered batch flush did not supply its own backend deadline")
	}
}

type closeAwareTSDBWriter struct {
	writeStarted chan struct{}
	releaseWrite chan struct{}
	closeCalled  chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
	writing      atomic.Bool
	closedActive atomic.Bool
	tenantCalls  atomic.Int64
	globalCalls  atomic.Int64
}

func (w *closeAwareTSDBWriter) Write(ctx context.Context, _ []Series) error {
	w.tenantCalls.Add(1)
	w.writing.Store(true)
	defer w.writing.Store(false)
	w.startOnce.Do(func() { close(w.writeStarted) })
	select {
	case <-w.releaseWrite:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *closeAwareTSDBWriter) WriteGlobal(context.Context, []Series) error {
	w.globalCalls.Add(1)
	return nil
}

func (w *closeAwareTSDBWriter) Close() error {
	if w.writing.Load() {
		w.closedActive.Store(true)
	}
	w.closeOnce.Do(func() { close(w.closeCalled) })
	return nil
}

func TestBatchingWriterCloseWaitsForInFlightFlush(t *testing.T) {
	under := &closeAwareTSDBWriter{
		writeStarted: make(chan struct{}),
		releaseWrite: make(chan struct{}),
		closeCalled:  make(chan struct{}),
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(under.releaseWrite) }) })

	batching := NewBatchingWriter(under, 500, time.Millisecond)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- batching.Write(
			context.Background(),
			[]Series{tenantSeries("probe_up")},
		)
	}()
	select {
	case <-under.writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timer flush did not reach the TSDB backend")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- batching.Close() }()
	select {
	case <-under.closeCalled:
		t.Fatal("TSDB backend closed while a batch mutation was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(under.releaseWrite) })
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("batched write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return after the backend mutation completed")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close batching writer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the in-flight mutation completed")
	}
	if under.closedActive.Load() {
		t.Fatal("backend Close overlapped an active TSDB mutation")
	}
}

func TestBatchingWriterRejectsWritesAfterClose(t *testing.T) {
	release := make(chan struct{})
	close(release)
	under := &closeAwareTSDBWriter{
		writeStarted: make(chan struct{}),
		releaseWrite: release,
		closeCalled:  make(chan struct{}),
	}
	batching := NewBatchingWriter(under, 500, time.Millisecond)
	if err := batching.Close(); err != nil {
		t.Fatalf("close batching writer: %v", err)
	}
	if err := batching.Write(
		context.Background(),
		[]Series{tenantSeries("probe_up")},
	); err == nil {
		t.Error("tenant Write after Close reached the closed TSDB backend")
	}
	if err := batching.WriteGlobal(
		context.Background(),
		[]Series{{Metric: "probectl_self_uptime_seconds", Value: 1}},
	); err == nil {
		t.Error("global Write after Close reached the closed TSDB backend")
	}
	if got := under.tenantCalls.Load(); got != 0 {
		t.Fatalf("post-close tenant backend calls = %d, want 0", got)
	}
	if got := under.globalCalls.Load(); got != 0 {
		t.Fatalf("post-close global backend calls = %d, want 0", got)
	}
}
