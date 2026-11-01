// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package fairness

import (
	"context"
	"testing"
	"time"
)

func TestEntityEvidenceHasBoundedSeparateTenantCredits(t *testing.T) {
	gate := NewGate(Policy{ResultsPerSec: 1, BurstSeconds: 1}, nil)
	gate.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	ctx := context.Background()
	if !gate.AdmitN(ctx, "tenant-a", MeterEntityEvidence, 1) ||
		gate.AdmitN(ctx, "tenant-a", MeterEntityEvidence, 1) {
		t.Fatal("entity evidence did not use a bounded tenant bucket")
	}
	if !gate.AdmitN(ctx, "tenant-b", MeterEntityEvidence, 1) {
		t.Fatal("one tenant spent another tenant's evidence credits")
	}
	if !gate.AdmitN(ctx, "tenant-a", MeterResults, 1) {
		t.Fatal("canonical evidence spent raw result credits")
	}
}
