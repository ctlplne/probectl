// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestSuperviseRestartsErroringConsumer is the ARCH-002 acceptance test: a core
// consumer whose Run returns an error must be RESTARTED by the supervisor —
// while a sibling on the SAME errgroup (the "API server") keeps serving and the
// group does NOT exit. Before this, an unsupervised consumer's error cancelled
// the shared errgroup and took the API + every plane down.
func TestSuperviseRestartsErroringConsumer(t *testing.T) {
	log := quietLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var starts atomic.Int32
	apiAlive := make(chan struct{})

	g, gctx := errgroup.WithContext(ctx)

	// The "API server": a long-running sibling that must stay up.
	g.Go(func() error {
		close(apiAlive)
		<-gctx.Done()
		return nil
	})

	// A core consumer that errors on its first run, then blocks (healthy).
	g.Go(func() error {
		return superviseRestart(gctx, "test-consumer", log, func(c context.Context) error {
			n := starts.Add(1)
			if n == 1 {
				return errors.New("transient subscribe failure")
			}
			<-c.Done() // healthy on restart
			return nil
		})
	})

	// The consumer must restart (>=2 starts) and the group must still be running.
	deadline := time.After(5 * time.Second)
	for starts.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("consumer was not restarted (starts=%d)", starts.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}

	// The API sibling must still be alive (the group did not cancel on the error).
	select {
	case <-apiAlive:
	default:
		t.Fatal("API sibling never started")
	}
	if gctx.Err() != nil {
		t.Fatal("errgroup was cancelled by the consumer error (API would be down)")
	}

	// Clean shutdown returns nil from both.
	cancel()
	if err := g.Wait(); err != nil {
		t.Fatalf("group should exit cleanly on shutdown, got: %v", err)
	}
}

// TestSuperviseRecoversPanic: a panicking consumer is recovered and restarted by
// the supervisor rather than crashing the process (ARCH-002).
func TestSuperviseRecoversPanic(t *testing.T) {
	log := quietLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var starts atomic.Int32
	done := make(chan struct{})
	go func() {
		_ = superviseRestart(ctx, "panicky", log, func(c context.Context) error {
			n := starts.Add(1)
			if n == 1 {
				panic("boom")
			}
			<-c.Done()
			return nil
		})
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for starts.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("panicking consumer was not restarted (starts=%d)", starts.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not return after shutdown")
	}
}
