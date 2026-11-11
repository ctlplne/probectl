// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestCapacityAgreementBillInputKeepsWideBoundsAndExactRecordedVersion(t *testing.T) {
	input := flow.CapacityBillRequest{Version: "9007199254740993", At: "2026-10-15T12:00:00.123456789+05:45", MaximumPollGap: "5m0.000000001s",
		PhysicalBounds: []flow.CapacityPhysicalBound{{ContextID: "11111111-1111-4111-8111-111111111111", InterfaceID: "22222222-2222-4222-8222-222222222222", MaxBPS: "18446744073709551615"}}}
	got, err := capacityBillInput(input, 1<<20)
	key := capacityBillMemberKey{input.PhysicalBounds[0].ContextID, input.PhysicalBounds[0].InterfaceID}
	if err != nil || got.bounds[key] != ^uint64(0) || got.at.Nanosecond() != 123456789 || got.gap != 5*time.Minute+time.Nanosecond {
		t.Fatal("exact version, physical bound or clock was narrowed", got, err)
	}
	for _, alter := range []func(*flow.CapacityBillRequest){
		func(in *flow.CapacityBillRequest) { in.Version = "1.0" },
		func(in *flow.CapacityBillRequest) { in.MaximumPollGap = "0s" },
		func(in *flow.CapacityBillRequest) {
			in.PhysicalBounds = append(in.PhysicalBounds, in.PhysicalBounds[0])
		},
		func(in *flow.CapacityBillRequest) { in.PhysicalBounds[0].MaxBPS = "18446744073709551616" },
	} {
		changed := input
		changed.PhysicalBounds = append([]flow.CapacityPhysicalBound(nil), input.PhysicalBounds...)
		alter(&changed)
		if _, err := capacityBillInput(changed, 1<<20); err == nil {
			t.Fatal("ambiguous or unrepresentable assumption was admitted", changed)
		}
	}
}
