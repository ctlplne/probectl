// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"
)

// superviseRestart runs a subsystem and RESTARTS it with bounded, jittered
// backoff if it returns an error OR panics, instead of letting that one failure
// cancel the whole errgroup and take the control plane down (ARCH-020, ARCH-002).
//
// Before this, every consumer rode a single errgroup: a transient failure in,
// say, the carbon or topology consumer returned an error that cancelled the
// group and killed the API server, the result pipeline, and every other plane
// with it. ARCH-002 extends supervision to the CORE ingest consumers (result /
// flow / device / endpoint / topology / OTLP receiver+consumers) and the
// result-fan, so a transient broker/registry fault while (re)establishing a
// subscription restarts just that consumer. Only the API server (srv.Run) and
// migrations stay fatal by design — if they can't run, the process SHOULD exit.
// A panic in a supervised subsystem is recovered (runRecovered) and treated as
// a restartable failure, never a process crash.
//
// It returns nil only when ctx is cancelled (clean shutdown); it never returns
// the subsystem's error, by design — the whole point is that a sidecar failure
// is not fatal to the group.
func superviseRestart(ctx context.Context, name string, log *slog.Logger, run func(context.Context) error) error {
	const (
		baseBackoff = 1 * time.Second
		maxBackoff  = 30 * time.Second
	)
	backoff := baseBackoff
	for {
		err := runRecovered(name, log, run, ctx)
		if ctx.Err() != nil {
			return nil // shutting down — not a crash
		}
		if err == nil {
			// A clean return without shutdown is unexpected for a long-running
			// consumer; restart it (after a short pause) rather than silently
			// leaving the plane dead.
			log.Warn("supervised subsystem returned without error; restarting", "subsystem", name)
		} else {
			log.Error("supervised subsystem failed; restarting after backoff",
				"subsystem", name, "backoff", backoff.String(), "error", err.Error())
		}
		jitter := time.Duration(rand.Int64N(int64(backoff)/2 + 1))
		select {
		case <-time.After(backoff + jitter):
		case <-ctx.Done():
			return nil
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// runRecovered runs the subsystem and converts a PANIC into a returned error
// (ARCH-002), so a panicking consumer is restarted by the supervisor instead of
// unwinding the goroutine and crashing the process. A clean error/return is
// passed through unchanged.
func runRecovered(name string, log *slog.Logger, run func(context.Context) error, ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("supervised subsystem PANICKED; recovering and restarting",
				"subsystem", name, "panic", fmt.Sprint(r))
			err = fmt.Errorf("subsystem %s panicked: %v", name, r)
		}
	}()
	return run(ctx)
}
