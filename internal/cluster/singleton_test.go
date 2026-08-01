// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cluster

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLeaseState struct {
	mu     sync.Mutex
	holder string
	epoch  int64
}

type fakeLease struct {
	state  *fakeLeaseState
	holder string
	token  LeaseToken
}

func (l *fakeLease) Acquire(context.Context) (LeaseToken, bool, error) {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if l.state.holder != "" {
		return LeaseToken{}, false, nil
	}
	l.state.epoch++
	l.state.holder = l.holder
	l.token = LeaseToken{Name: "test", HolderID: l.holder, Epoch: l.state.epoch}
	return l.token, true, nil
}

func (l *fakeLease) Renew(_ context.Context, token LeaseToken) error {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if token != l.token || l.state.holder != l.holder || token.Epoch != l.state.epoch {
		return ErrLeaseFenced
	}
	return nil
}

func (l *fakeLease) Release(_ context.Context, token LeaseToken) error {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if token != l.token || l.state.holder != l.holder || token.Epoch != l.state.epoch {
		return ErrLeaseFenced
	}
	l.state.holder = ""
	l.token = LeaseToken{}
	return nil
}

func TestSingletonLeaseEpochFencesStaleHolder(t *testing.T) {
	state := &fakeLeaseState{}
	first := &fakeLease{state: state, holder: "replica-a"}
	second := &fakeLease{state: state, holder: "replica-b"}
	one, won, err := first.Acquire(context.Background())
	if err != nil || !won {
		t.Fatalf("first acquire won=%v err=%v", won, err)
	}
	if _, won, err := second.Acquire(context.Background()); err != nil || won {
		t.Fatalf("second acquire while held won=%v err=%v", won, err)
	}
	if err := first.Release(context.Background(), one); err != nil {
		t.Fatal(err)
	}
	two, won, err := second.Acquire(context.Background())
	if err != nil || !won || two.Epoch <= one.Epoch {
		t.Fatalf("failover token=%+v previous=%+v won=%v err=%v", two, one, won, err)
	}
	if err := first.Renew(context.Background(), one); !errors.Is(err, ErrLeaseFenced) {
		t.Fatalf("old epoch renewal = %v, want ErrLeaseFenced", err)
	}
}

func TestSingletonCoordinatorValidation(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	empty := newCoordinator(&fakeLease{state: &fakeLeaseState{}, holder: "empty"}, time.Millisecond, log)
	if err := empty.Run(context.Background()); err == nil {
		t.Fatal("coordinator without tasks must fail")
	}

	c := newCoordinator(&fakeLease{state: &fakeLeaseState{}, holder: "replica"}, time.Millisecond, log)
	noop := func(context.Context, LeaseToken) error { return nil }
	if err := c.Register("", noop); err == nil {
		t.Fatal("empty singleton task name must fail")
	}
	if err := c.Register("nil-task", nil); err == nil {
		t.Fatal("nil singleton task must fail")
	}
	if err := c.Register("task", noop); err != nil {
		t.Fatal(err)
	}
	if err := c.Register("task", noop); err == nil {
		t.Fatal("duplicate singleton task must fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Register("late", noop); err == nil {
		t.Fatal("registration after coordinator start must fail")
	}
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("starting a coordinator twice must fail")
	}
	if c.WithMetrics(nil) != c || c.isHolder() || c.currentEpoch() != 0 {
		t.Fatal("idle coordinator state must remain standby")
	}
	if _, err := NewPGLease(nil, "test", "replica"); err == nil {
		t.Fatal("PostgreSQL lease without a writer pool must fail")
	}
}

func TestSingletonTaskExitIsLeadershipFailure(t *testing.T) {
	token := LeaseToken{Name: "test", HolderID: "replica", Epoch: 1}
	t.Run("nil", func(t *testing.T) {
		err := runSingletonTasks(context.Background(), token, []SingletonTask{{
			Name: "stopped",
			Run:  func(context.Context, LeaseToken) error { return nil },
		}})
		if !errors.Is(err, ErrSingletonTaskStopped) {
			t.Fatalf("task return = %v, want ErrSingletonTaskStopped", err)
		}
	})
	t.Run("error", func(t *testing.T) {
		want := errors.New("loop failed")
		err := runSingletonTasks(context.Background(), token, []SingletonTask{{
			Name: "failed",
			Run:  func(context.Context, LeaseToken) error { return want },
		}})
		if !errors.Is(err, want) {
			t.Fatalf("task return = %v, want wrapped loop error", err)
		}
	})
}

func TestSingletonCoordinatorTwoReplicasFailoverNoDuplication(t *testing.T) {
	const interval = 75 * time.Millisecond
	state := &fakeLeaseState{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	first := newCoordinator(&fakeLease{state: state, holder: "replica-a"}, interval, log)
	second := newCoordinator(&fakeLease{state: state, holder: "replica-b"}, interval, log)

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
	if err := first.Register("side-effects", task); err != nil {
		t.Fatal(err)
	}
	if err := second.Register("side-effects", task); err != nil {
		t.Fatal(err)
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneA <- first.Run(ctxA) }()
	go func() { doneB <- second.Run(ctxB) }()
	defer func() {
		cancelA()
		cancelB()
	}()

	var initial LeaseToken
	select {
	case initial = <-starts:
	case <-time.After(time.Second):
		t.Fatal("neither replica acquired the singleton lease")
	}
	time.Sleep(2 * interval) // allow several renew/standby cycles
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("two replicas ran singleton work concurrently: max active=%d", got)
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
	case <-time.After(3 * interval):
		t.Fatal("standby did not take over within the bounded renewal window")
	}
	if elapsed := time.Since(failedAt); elapsed > 2*interval {
		t.Fatalf("singleton failover took %s, want no more than one retry interval plus scheduler allowance (%s)", elapsed, 2*interval)
	}
	if failover.HolderID == initial.HolderID || failover.Epoch <= initial.Epoch {
		t.Fatalf("failover token=%+v initial=%+v", failover, initial)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("old and new epochs overlapped: max active=%d", got)
	}

	cancelA()
	cancelB()
	for name, done := range map[string]<-chan error{"replica-a": doneA, "replica-b": doneB} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s coordinator: %v", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s coordinator did not stop", name)
		}
	}
}
