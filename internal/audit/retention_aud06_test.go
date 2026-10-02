// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"context"
	"testing"
	"time"
)

// TestMaskedSIEMExportDoesNotAuthorizePruning is the AUD-06 retention half: the
// tenant SIEM-delivery cursor is the pruning watermark, so if the SIEM copy is
// identity-masked (PROBECTL_SIEM_AUDIT_IDENTITY=pseudonymize) and the operator
// has not opted in, pruning past that watermark would destroy the only
// attributable copy. WithTenantExportAttributable(false) forces the tenant
// watermark to 0 so nothing is export-confirmed and the local full-fidelity
// rows are kept; attributable=true keeps the real watermark.
func TestMaskedSIEMExportDoesNotAuthorizePruning(t *testing.T) {
	const high = int64(999999)
	highWatermark := func(context.Context, string) (int64, error) { return high, nil }

	masked := NewRetentionRunnerPG(nil, RetentionPolicy{Window: time.Hour}, nil, nil).
		withTenantWatermarkForTest(highWatermark).
		WithTenantExportAttributable(false)
	if got, err := masked.tenantWatermark(context.Background(), "tenant-a"); err != nil || got != 0 {
		t.Fatalf("AUD-06: a masked SIEM export must not authorize pruning (watermark forced to 0), got %d err=%v", got, err)
	}

	attributable := NewRetentionRunnerPG(nil, RetentionPolicy{Window: time.Hour}, nil, nil).
		withTenantWatermarkForTest(highWatermark).
		WithTenantExportAttributable(true)
	if got, err := attributable.tenantWatermark(context.Background(), "tenant-a"); err != nil || got != high {
		t.Fatalf("AUD-06: an attributable (clear/opted-in) export keeps the real watermark, got %d err=%v", got, err)
	}
}
