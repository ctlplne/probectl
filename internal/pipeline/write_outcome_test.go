// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"testing"
)

func TestUnknownWriteOutcomeClassifiesContextDeadline(t *testing.T) {
	if !unknownWriteOutcome(context.Background(), context.DeadlineExceeded) {
		t.Fatal("deadline-exceeded write result must be treated as unknown")
	}
	if !unknownWriteOutcome(context.Background(), context.Canceled) {
		t.Fatal("canceled write result must be treated as unknown")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !unknownWriteOutcome(ctx, errors.New("store result lost after cancel")) {
		t.Fatal("canceled caller context must make the write outcome unknown")
	}
	if unknownWriteOutcome(context.Background(), errors.New("definitive store failure")) {
		t.Fatal("definitive non-context write failure must still be DLQ-eligible")
	}
}
