// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package breaker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestNeutralOutcomePreservesClosedFailuresAndHalfOpenState(t *testing.T) {
	var clock atomic.Int64
	b := New(2, time.Minute)
	b.now = func() time.Time { return time.Unix(0, clock.Load()) }
	down := errors.New("owned upstream down")
	_ = runBreakerErrorTest(b, func() error { return down })
	before := b.Stats()
	if err := b.DoWithOutcome(func() (Outcome, error) { return OutcomeNeutral, context.Canceled }); !errors.Is(err, context.Canceled) || b.Stats() != before {
		t.Fatal("neutral completion erased or increased prior failures", err, b.Stats())
	}
	_ = runBreakerErrorTest(b, func() error { return down })
	clock.Store(int64(2 * time.Minute))
	before = b.Stats()
	cooldown := b.openUntil
	if err := b.DoWithOutcome(func() (Outcome, error) { return OutcomeNeutral, context.DeadlineExceeded }); !errors.Is(err, context.DeadlineExceeded) || b.Stats() != before || !b.openUntil.Equal(cooldown) {
		t.Fatal("neutral probe manufactured recovery or rearmed cooldown", err, b.Stats())
	}
	if err := runBreakerErrorTest(b, func() error { return nil }); err != nil || b.Stats().State != StateClosed {
		t.Fatal("neutral probe retained admission after ending", err)
	}
}

func TestOldNeutralRequestCannotReleaseAnotherRequestsHalfOpenProbe(t *testing.T) {
	var clock atomic.Int64
	b := New(1, time.Minute)
	b.now = func() time.Time { return time.Unix(0, clock.Load()) }
	oldStarted, oldRelease, oldDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-oldRelease:
		default:
			close(oldRelease)
		}
	})
	go func() {
		defer close(oldDone)
		_ = b.DoWithOutcome(func() (Outcome, error) { close(oldStarted); <-oldRelease; return OutcomeNeutral, context.Canceled })
	}()
	<-oldStarted
	_ = runBreakerErrorTest(b, func() error { return errors.New("down") })
	clock.Store(int64(2 * time.Minute))
	probeStarted, probeRelease, probeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-probeRelease:
		default:
			close(probeRelease)
		}
	})
	go func() {
		defer close(probeDone)
		_ = runBreakerErrorTest(b, func() error { close(probeStarted); <-probeRelease; return nil })
	}()
	<-probeStarted
	close(oldRelease)
	<-oldDone
	called := false
	if err := runBreakerErrorTest(b, func() error { called = true; return nil }); !errors.Is(err, ErrOpen) || called {
		t.Fatal("an older neutral caller released someone else's probe", err)
	}
	close(probeRelease)
	<-probeDone
	if b.Stats().State != StateClosed {
		t.Fatal("actual successful probe did not recover")
	}
}

func TestClassifiedHealthKeepsApplicationErrorAndRejectsInvalidOutcome(t *testing.T) {
	b := New(1, time.Minute)
	application := errors.New("owned application refusal")
	if err := b.DoWithOutcome(func() (Outcome, error) { return OutcomeSuccess, application }); err != application || b.Stats().State != StateClosed {
		t.Fatal("responding application error was lost or poisoned health", err)
	}
	if err := b.DoWithOutcome(func() (Outcome, error) { return Outcome(255), nil }); !errors.Is(err, ErrInvalidOutcome) || b.Stats().State != StateOpen {
		t.Fatal("invalid trusted classification manufactured a pass", err)
	}
}
