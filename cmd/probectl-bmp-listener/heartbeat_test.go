// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// DPR-084: the listener beats at start and on every tick, keeps going after a
// failed beat, and stops with the context — liveness never gates serving.
func TestHeartbeatLoopBeatsImmediatelyThenEveryInterval(t *testing.T) {
	var beats atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		heartbeatLoop(ctx, 20*time.Millisecond, func(context.Context) error {
			n := beats.Add(1)
			if n == 2 {
				return errors.New("registry blinked")
			}
			return nil
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for beats.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if got := beats.Load(); got < 4 {
		t.Fatalf("beats = %d, want the immediate beat plus ticks, surviving a failed beat", got)
	}
}
