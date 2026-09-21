// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tsdb

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type writeFencedWriter struct {
	next  Writer
	fence tenancy.WriterFence
}

// WithTenantWriteFence guards a tenant-owned TSDB mutation with the durable
// lifecycle lease. When the production batching writer is present, its inner
// backend is decorated so the lease spans the actual background flush even if
// a canceled caller returns before that shared mutation completes.
func WithTenantWriteFence(next Writer, fence tenancy.WriterFence) Writer {
	if next == nil {
		return nil
	}
	if HasTenantWriteFence(next) {
		return next
	}
	if batching, ok := next.(*BatchingWriter); ok {
		batching.w = WithTenantWriteFence(batching.w, fence)
		return batching
	}
	return &writeFencedWriter{next: next, fence: fence}
}

func (w *writeFencedWriter) Write(
	ctx context.Context,
	series []Series,
) error {
	if len(series) == 0 {
		return nil
	}
	if err := ValidateTenantSeries(series); err != nil {
		return err
	}
	return tenancy.FencedWrite(ctx, w.fence, series,
		func(s Series) string { return s.Labels[TenantLabel] }, ErrTenantRequired,
		func(ctx context.Context) error { return w.next.Write(ctx, series) })
}

// WriteGlobal preserves the explicit non-tenant self-metrics escape hatch.
// Global series are validated and forwarded without a tenant lifecycle lease;
// tenant-owned callers cannot enter this path because tenant_id is forbidden.
func (w *writeFencedWriter) WriteGlobal(
	ctx context.Context,
	series []Series,
) error {
	if len(series) == 0 {
		return nil
	}
	if err := ValidateGlobalSeries(series); err != nil {
		return err
	}
	return WriteGlobal(ctx, w.next, series)
}

func (w *writeFencedWriter) Close() error {
	return w.next.Close()
}

// UnderlyingWriter removes writer-fence and batching decorators so lifecycle,
// query, and backend-specific diagnostic code can retain their narrow optional
// capabilities without allowing tenant writes around the production seams.
func UnderlyingWriter(writer Writer) Writer {
	for {
		switch current := writer.(type) {
		case *writeFencedWriter:
			writer = current.next
		case *BatchingWriter:
			writer = current.w
		default:
			return writer
		}
	}
}

// HasTenantWriteFence reports whether this writer's tenant mutation path is
// protected by the durable lifecycle lease.
func HasTenantWriteFence(writer Writer) bool {
	for {
		switch current := writer.(type) {
		case *writeFencedWriter:
			return true
		case *BatchingWriter:
			writer = current.w
		default:
			return false
		}
	}
}
