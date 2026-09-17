// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
