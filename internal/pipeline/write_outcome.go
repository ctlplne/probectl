// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
)

// unknownWriteOutcome reports the cancellation/deadline race where a store call
// may have landed but the caller can no longer observe the result.
//
// In that state the safe bus action is the result pipeline's existing contract:
// return an error so the offset remains uncommitted. Do not DLQ the original
// bytes, because replaying a batch that may already be durable creates a second
// copy whenever the backing store lacks perfect idempotence for that shape.
func unknownWriteOutcome(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
