// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"
)

// superviseRestart runs a non-critical subsystem and RESTARTS it with bounded,
// jittered backoff if it returns an error, instead of letting that one failure
// cancel the whole errgroup and take the control plane down (ARCH-020).
//
// Before this, every consumer rode a single errgroup: a transient failure in,
// say, the carbon or topology consumer returned an error that cancelled the
// group and killed the API server, the result pipeline, and every other plane
// with it. Core subsystems (the result pipeline, the API server, migrations)
// stay fatal — if they can't run, the process SHOULD exit. But a sidecar plane
// failing should degrade only that plane while it retries.
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
		err := run(ctx)
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
