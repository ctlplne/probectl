// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCapacityForecastInputKeepsExactWindowsThresholdAndIndependentBounds(t *testing.T) {
	const contextID = "11111111-1111-4111-8111-111111111111"
	const interfaceID = "22222222-2222-4222-8222-222222222222"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(contextID))
	budget := flowstore.DefaultExplorerBudget()
	input := flow.CapacityForecastRequest{Target: flow.CapacityTarget{Kind: "interface", ContextID: contextID, InterfaceID: interfaceID}, From: "2026-10-01T12:00:00.123456789+05:45", To: "2026-10-15T12:00:00.123456789+05:45", Until: "2026-10-20T12:00:00.123456789+05:45", Direction: "max_directional_percentiles", CapacityBPS: "9007199254740993.000000000000000001", MaximumPollGap: "5m", PhysicalBounds: []flow.CapacityPhysicalBound{{ContextID: contextID, InterfaceID: interfaceID, MaxBPS: "18446744073709551615"}}}
	got, err := capacityForecastInput(ctx, input, budget)
	if err != nil || got.capacity != input.CapacityBPS || got.from.Nanosecond() != 123456789 || got.counter.bounds[capacityBillMemberKey{contextID, interfaceID}] != ^uint64(0) {
		t.Fatal("exact forecast input was narrowed or bound to financial terms", got, err)
	}
	for _, change := range []func(*flow.CapacityForecastRequest){
		func(i *flow.CapacityForecastRequest) { i.CapacityBPS = "0" },
		func(i *flow.CapacityForecastRequest) { i.CapacityBPS = "1/3" },
		func(i *flow.CapacityForecastRequest) { i.Until = i.To },
		func(i *flow.CapacityForecastRequest) { i.To = i.From },
		func(i *flow.CapacityForecastRequest) { i.Target.TagID = contextID },
	} {
		altered := input
		change(&altered)
		if _, err := capacityForecastInput(ctx, altered, budget); err == nil {
			t.Fatal("ambiguous or unsupported forecast input was admitted", altered)
		}
	}
	if _, err := capacityForecastInput(t.Context(), input, budget); err == nil {
		t.Fatal("forecast threshold calculation preceded tenant boundary")
	}
}
