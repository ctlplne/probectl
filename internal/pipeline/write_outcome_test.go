// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
