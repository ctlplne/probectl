// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// recoverHandler runs handler and converts a PANIC into an error, so a buggy
// subscriber handler can never crash the whole consumer process (ING-40).
//
// Every transport (memory/kafka/nats) delivers records to the handler on
// goroutines it spawns itself, with no defer-recover above them. A single panic
// — a nil-map write, an out-of-range index deep in a decode path — therefore
// took down the entire control plane, and on a durable broker the uncommitted
// poison record crash-looped the process on every restart.
//
// A recovered panic is:
//   - COUNTED via panics (never silent — the CORRECT-007/ING-12 "a loss is always
//     accounted" contract), so it surfaces on the bus Stats/HandlerPanics
//     counters an operator already watches;
//   - LOGGED through slog WITHOUT the record key or value: a payload may carry
//     another tenant's data or a secret (docs/guardrails.md G7-6), so only the
//     topic and the recovered value are emitted;
//   - returned as an ERROR, which routes the record through the SAME
//     bounded-redelivery / dead-letter path a handler error already takes. A
//     transient panic gets its redeliveries; a permanently-panicking record is
//     eventually terminated and accounted (HandlerLost / DLQ) rather than looping
//     forever or vanishing.
//
// The goroutine returns normally and keeps draining the next record.
func recoverHandler(ctx context.Context, handler Handler, msg Message, panics *atomic.Uint64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if panics != nil {
				panics.Add(1)
			}
			slog.Default().Error("bus: recovered panic in subscriber handler — record failed, process preserved (ING-40)",
				"topic", msg.Topic, "panic", fmt.Sprint(r))
			err = fmt.Errorf("bus: subscriber handler panicked: %v", r)
		}
	}()
	return handler(ctx, msg)
}
