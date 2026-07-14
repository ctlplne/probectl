// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
