// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"errors"
	"testing"
	"time"
)

func TestWorkerDeadlineUsesAuthoritativeRemainingDurationDespiteClockSkew(t *testing.T) {
	sent := time.Now()
	for _, skew := range []time.Duration{-48 * time.Hour, 0, 48 * time.Hour} {
		clock := sent.Add(skew).Round(0)
		for _, remaining := range []time.Duration{time.Microsecond, time.Second, time.Minute} {
			deadline, err := projectFlowLeaseDeadline(sent, clock, clock.Add(remaining), time.Minute)
			if err != nil || deadline != sent.Add(remaining) {
				t.Fatal("remote wall clock changed local monotonic IO allowance", err, skew, remaining)
			}
		}
	}
	for _, until := range []time.Time{sent.Add(-time.Second), sent, sent.Add(time.Minute + time.Microsecond)} {
		if deadline, err := projectFlowLeaseDeadline(sent, sent, until, time.Minute); !errors.Is(err, ErrJournalLease) || !deadline.IsZero() {
			t.Fatal("expired/unbounded database projection became an IO lease", err)
		}
	}
	if !(WorkLease{}).Deadline().IsZero() {
		t.Fatal("empty lease acquired a local deadline")
	}
}
