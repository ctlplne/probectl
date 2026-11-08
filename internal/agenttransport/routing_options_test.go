// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

func TestRoutingCapturePolicyKeepsConfiguredAdmissionAcrossOptionOrder(t *testing.T) {
	limits := defaultRoutingTransportLimits()
	profile := store.BGPRoutingBudget{MemoryBytes: 2 << 30, WorkUnits: 8 << 30, StateBytes: 1 << 40, LeaseDuration: 24 * time.Hour}
	for _, option := range []Option{WithRoutingCaptureStateBytes(2 << 40), WithRoutingLimits(profile, 24*time.Hour, 8<<20)} {
		if err := option(&limits); err != nil {
			t.Fatal(err)
		}
	}
	budget := (&service{routingLimits: limits}).routingCaptureBudget()
	if budget.MemoryBytes != profile.MemoryBytes || budget.WorkUnits != profile.WorkUnits || budget.StateBytes != 2<<40 || budget.PublicSourceMaxAge != 24*time.Hour || budget.LeaseDuration != time.Minute || limits.public.StateBytes != 1<<40 || limits.receiveBytes != 8<<20 {
		t.Fatal("flow capture clamped configured complete-source admission or mixed independent state/age policies", budget, limits)
	}
	for _, invalid := range []int64{0, -1} {
		if err := WithRoutingCaptureStateBytes(invalid)(&limits); err == nil {
			t.Fatal("unbounded capture state reached the listener", invalid)
		}
	}
	defaults := (&service{}).routingCaptureBudget()
	if defaults.MemoryBytes != 512<<20 || defaults.WorkUnits != 2<<30 || defaults.StateBytes != 64<<30 || defaults.PublicSourceMaxAge != 12*time.Hour {
		t.Fatal("capture defaults cannot retain complete public metadata", defaults)
	}
}
