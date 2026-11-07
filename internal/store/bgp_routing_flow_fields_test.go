// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRoutingFlowProjectionKeepsEveryPathAndRejectsPartialAdmission(t *testing.T) {
	paths := []BGPRoutingChange{routingChangeFixture(), routingChangeFixture()}
	paths[1].HasPathID, paths[1].PathID = false, 0
	paths[1].Segments = []BGPRoutingSegment{{Kind: 2, Values: []uint32{65010, 65010, 4000000000}}}
	fields, err := routingFlowPathFields(t.Context(), paths, routingViewBudget())
	if err != nil || len(fields) != 2 || fields[0].ASPathText != "(64496) 4294967295 64497 64497 {64500,64501}" || fields[0].OriginAS != nil || fields[1].ASPathText != "65010 65010 4000000000" || fields[1].OriginAS == nil || *fields[1].OriginAS != 4000000000 || fields[1].FirstTransitAS == nil || *fields[1].FirstTransitAS != 65010 {
		t.Fatal("complete flow routing projection lost path correspondence or semantics", fields, err)
	}
	fields[1].ASPath[0].Values[0] = 1
	if !reflect.DeepEqual(paths[1].Segments[0].Values, []uint32{65010, 65010, 4000000000}) {
		t.Fatal("retained flow projection mutated its owned route source")
	}
	for _, budget := range []BGPRoutingBudget{{}, {MemoryBytes: 1000, WorkUnits: 8 << 20}, {MemoryBytes: 8 << 20, WorkUnits: 10}} {
		if got, err := routingFlowPathFields(t.Context(), paths, budget); !errors.Is(err, ErrBGPRoutingBudget) || got != nil {
			t.Fatal("unadmitted complete flow projection returned partial paths", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := routingFlowPathFields(ctx, paths, routingViewBudget()); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("cancelled flow projection returned partial paths", err)
	}
}
