// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/store"
)

func TestRoutingProjectionKeepsWholePopulationAndAdmitsDescriptorExpansion(t *testing.T) {
	group := bgp.RoutingChangeGroup{Family: bgp.RouteFamily{AFI: 1, SAFI: 1}, NextHops: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	for i := range 5001 {
		group.Announced = append(group.Announced, bgp.RoutePrefix{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32), HasPathID: true, PathID: 4294967295})
	}
	decoded := bgp.RoutingChanges{Groups: []bgp.RoutingChangeGroup{group}, Attributes: []bgp.RouteAttribute{{Flags: 64, Type: 1, Value: []byte{0}}, {Flags: 64, Type: 2, Value: []byte{}}}}
	profile := store.BGPRoutingBudget{MemoryBytes: 256 << 20, WorkUnits: 256 << 20, StateBytes: 1 << 30}
	batches := []store.BGPRoutingBatch{{AFI: 1, SAFI: 1}}
	got, err := projectRoutingChanges(t.Context(), batches, decoded, profile)
	if err != nil || len(got) != 1 || len(got[0].Changes) != 5001 || got[0].Changes[5000].PathID != 4294967295 || got[0].Changes[5000].Segments == nil || len(got[0].Changes[5000].Attributes.Wire) != 2 || got[0].Changes[5000].Attributes.Wire[1].Value == nil {
		t.Fatal("complete routing projection lost population, exact path or empty presence", err)
	}
	decoded.Attributes = make([]bgp.RouteAttribute, 5001)
	if out, err := projectRoutingChanges(t.Context(), []store.BGPRoutingBatch{{AFI: 1, SAFI: 1}}, decoded, profile); err == nil || out != nil {
		t.Fatal("routing descriptor expansion escaped complete resource admission")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if out, err := projectRoutingChanges(ctx, []store.BGPRoutingBatch{{AFI: 1, SAFI: 1}}, decoded, profile); err == nil || out != nil {
		t.Fatal("canceled routing projection exposed partial paths")
	}
}
