// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// flakyEmitter fails the first failN Emit calls, then succeeds.
type flakyEmitter struct {
	failN int
	calls atomic.Int64
}

func (e *flakyEmitter) Emit(_ context.Context, _ []Record) error {
	if int(e.calls.Add(1)) <= e.failN {
		return errors.New("bus down")
	}
	return nil
}

// CORRECT-001: a transient emit failure is RETRIED (records not lost); a
// permanent failure DROPS the batch but COUNTS it (DroppedRecords) — never a
// silent loss.
func TestFlowEmitRetryThenDrop(t *testing.T) {
	batch := []Record{{TenantID: "t", AgentID: "a"}, {TenantID: "t", AgentID: "a"}}

	// Transient: fails twice, succeeds on the third attempt (within 1+2 retries).
	c, err := New(testConfig(), &flakyEmitter{failN: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) {} // no real backoff in tests
	c.flushBatch(context.Background(), batch)
	if s := c.StatsSnapshot(); s.Records != 2 || s.DroppedRecords != 0 || s.EmitErrors != 0 {
		t.Fatalf("transient emit must retry to success, no loss: %+v", s)
	}

	// Permanent: every attempt fails → the batch is dropped AND counted.
	c2, err := New(testConfig(), &flakyEmitter{failN: 1 << 30}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2.sleep = func(context.Context, time.Duration) {}
	c2.flushBatch(context.Background(), batch)
	if s := c2.StatsSnapshot(); s.DroppedRecords != 2 || s.Records != 0 || s.EmitErrors != 1 {
		t.Fatalf("permanent emit must drop + count the records: %+v", s)
	}
}
