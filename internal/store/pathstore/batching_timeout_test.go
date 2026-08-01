// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathstore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

type pathFlushContext struct {
	deadlineSet bool
	remaining   time.Duration
}

type cancellationWaitingPathStore struct {
	observed chan pathFlushContext
	finished chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (s *cancellationWaitingPathStore) Save(
	ctx context.Context,
	_ string,
	_ *path.Path,
) error {
	deadline, ok := ctx.Deadline()
	observation := pathFlushContext{deadlineSet: ok}
	if ok {
		observation.remaining = time.Until(deadline)
	}
	s.observed <- observation
	defer s.once.Do(func() { close(s.finished) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.release:
		return errors.New("test cleanup released unbounded path flush")
	}
}

func (s *cancellationWaitingPathStore) Latest(
	context.Context,
	string,
	string,
) (*path.Path, bool, error) {
	return nil, false, nil
}

func (s *cancellationWaitingPathStore) History(
	context.Context,
	string,
	string,
	HistoryQuery,
) ([]Snapshot, error) {
	return nil, nil
}

func (s *cancellationWaitingPathStore) Close() error { return nil }

func TestBatchingSaverBackgroundFlushIsBounded(t *testing.T) {
	inner := &cancellationWaitingPathStore{
		observed: make(chan pathFlushContext, 1),
		finished: make(chan struct{}),
		release:  make(chan struct{}),
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(inner.release) }) })

	batching := NewBatchingSaver(
		inner,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Millisecond,
		32,
	)
	if err := batching.Save(
		context.Background(),
		"tenant-a",
		&path.Path{},
	); err != nil {
		t.Fatalf("queue path: %v", err)
	}

	var observation pathFlushContext
	select {
	case observation = <-inner.observed:
	case <-time.After(2 * time.Second):
		t.Fatal("background path flush did not reach the backend")
	}
	if !observation.deadlineSet {
		t.Fatal("background path flush received an unbounded context")
	}
	if observation.remaining <= 0 || observation.remaining > 10*time.Second {
		t.Fatalf("background path flush deadline remaining = %v, want a small positive bound", observation.remaining)
	}

	select {
	case <-inner.finished:
	case <-time.After(7 * time.Second):
		t.Fatal("background path flush did not return after its context deadline")
	}
	deadline := time.Now().Add(time.Second)
	for batching.lostCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := batching.lostCount(); got != 1 {
		t.Fatalf("timed-out background path flush recorded lost = %d, want 1", got)
	}
}
