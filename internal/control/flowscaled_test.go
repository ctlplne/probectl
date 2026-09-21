// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

// CORRECT-001: analytics volume math must use the sampling-scaled byte count.
// A flow sampled at rate=64 reports raw Bytes that undercount true volume ~64x;
// BytesScaled carries the corrected value. scaledFlowBytes returns the scaled
// value when present and falls back to raw bytes for unsampled exporters.
func TestScaledFlowBytes(t *testing.T) {
	// Sampled (rate=64): raw 1500, scaled 96000. Analytics must see 96000.
	sampled := &flowv1.FlowRecord{Bytes: 1500, BytesScaled: 96000, SamplingRate: 64}
	if got := scaledFlowBytes(sampled); got != 96000 {
		t.Fatalf("sampled: scaledFlowBytes = %d, want 96000 (rate-adjusted)", got)
	}
	// Unsampled exporter leaves BytesScaled zero: fall back to raw bytes.
	unsampled := &flowv1.FlowRecord{Bytes: 1500, BytesScaled: 0}
	if got := scaledFlowBytes(unsampled); got != 1500 {
		t.Fatalf("unsampled: scaledFlowBytes = %d, want 1500 (raw)", got)
	}
}
