// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathstore

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/path"
)

type closeAwarePathStore struct {
	writeStarted chan struct{}
	releaseWrite chan struct{}
	closeCalled  chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
	writing      atomic.Bool
	closedActive atomic.Bool
}

func (s *closeAwarePathStore) SaveBatch(ctx context.Context, _ []PathItem) error {
	s.writing.Store(true)
	defer s.writing.Store(false)
	s.startOnce.Do(func() { close(s.writeStarted) })
	select {
	case <-s.releaseWrite:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*closeAwarePathStore) Save(context.Context, string, *path.Path) error {
	return nil
}

func (*closeAwarePathStore) Latest(
	context.Context,
	string,
	string,
) (*path.Path, bool, error) {
	return nil, false, nil
}

func (*closeAwarePathStore) History(
	context.Context,
	string,
	string,
	HistoryQuery,
) ([]Snapshot, error) {
	return nil, nil
}

func (s *closeAwarePathStore) Close() error {
	if s.writing.Load() {
		s.closedActive.Store(true)
	}
	s.closeOnce.Do(func() { close(s.closeCalled) })
	return nil
}

func TestBatchingSaverCloseWaitsForInFlightFlush(t *testing.T) {
	inner := &closeAwarePathStore{
		writeStarted: make(chan struct{}),
		releaseWrite: make(chan struct{}),
		closeCalled:  make(chan struct{}),
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(inner.releaseWrite) }) })

	batching := NewBatchingSaver(
		inner,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Millisecond,
		32,
	)
	if err := batching.Save(context.Background(), "tenant-a", &path.Path{}); err != nil {
		t.Fatalf("queue path: %v", err)
	}
	select {
	case <-inner.writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timer flush did not reach the backend")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- batching.Close() }()
	select {
	case <-inner.closeCalled:
		t.Fatal("backend closed while a path batch mutation was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(inner.releaseWrite) })
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close batching saver: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the in-flight flush completed")
	}
	if inner.closedActive.Load() {
		t.Fatal("backend Close overlapped an active path mutation")
	}
}

func TestBatchingSaverRejectsSaveAfterClose(t *testing.T) {
	inner := &closeAwarePathStore{
		writeStarted: make(chan struct{}),
		releaseWrite: make(chan struct{}),
		closeCalled:  make(chan struct{}),
	}
	batching := NewBatchingSaver(
		inner,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Hour,
		32,
	)
	if err := batching.Close(); err != nil {
		t.Fatalf("close batching saver: %v", err)
	}
	if err := batching.Save(context.Background(), "tenant-a", &path.Path{}); err == nil {
		t.Fatal("Save after Close succeeded; the accepted path can never be flushed")
	}
}
