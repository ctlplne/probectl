// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"
)

func routingChangeFixture() BGPRoutingChange {
	return BGPRoutingChange{Prefix: netip.MustParsePrefix("192.0.2.0/24"), HasPathID: true, PathID: math.MaxUint32,
		Segments:   []BGPRoutingSegment{{Kind: 3, Values: []uint32{64496}}, {Kind: 2, Values: []uint32{math.MaxUint32, 64497, 64497}}, {Kind: 1, Values: []uint32{64500, 64501}}},
		Attributes: BGPRoutingAttributes{Wire: []BGPRoutingAttribute{{Flags: 64, Type: 1, Value: []byte{0}}, {Flags: 64, Type: 2, Value: []byte{}}, {Flags: 192, Type: 255, Value: []byte{0, 255}}, {Flags: 192, Type: 255, Value: nil}}},
		NextHops:   []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")}}
}

func TestBGPRoutingBatchKeepsCompleteValuesAndReplayIdentity(t *testing.T) {
	batch := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: time.Now(), Changes: []BGPRoutingChange{routingChangeFixture()}}
	prepared, digest, err := prepareRoutingBatch(t.Context(), batch, 1, 1, routingViewBudget())
	if err != nil || len(prepared) != 1 || digest == ([32]byte{}) {
		t.Fatal("complete routing batch was refused", err)
	}
	var segments []BGPRoutingSegment
	var attributes BGPRoutingAttributes
	if err := json.Unmarshal(prepared[0].segments, &segments); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(prepared[0].attributes, &attributes); err != nil {
		t.Fatal(err)
	}
	if prepared[0].PathID != math.MaxUint32 || segments[0].Kind != 3 || segments[1].Values[0] != math.MaxUint32 ||
		segments[1].Values[1] != segments[1].Values[2] || segments[2].Kind != 1 || len(attributes.Wire) != 4 ||
		attributes.Wire[1].Value == nil || attributes.Wire[3].Value != nil || len(prepared[0].hops) != 2 || prepared[0].hops[1] != "fe80::1" {
		t.Fatal("routing batch lost complete path identity, segments, attributes or next hops")
	}
	_, same, err := prepareRoutingBatch(t.Context(), batch, 1, 1, routingViewBudget())
	if err != nil || digest != same {
		t.Fatal("unchanged batch changed replay identity", err)
	}
	batch.WireDigest = make([]byte, 32)
	_, wire, err := prepareRoutingBatch(t.Context(), batch, 1, 1, routingViewBudget())
	if err != nil || wire == digest {
		t.Fatal("complete wire bytes were absent from routing replay identity", err)
	}
	batch.WireDigest[0] = 1
	_, alteredWire, err := prepareRoutingBatch(t.Context(), batch, 1, 1, routingViewBudget())
	if err != nil || wire == alteredWire {
		t.Fatal("changed original frame kept routing replay identity", err)
	}
	batch.WireDigest = nil
	batch.Changes[0].Attributes.Wire[2].Value[0] = 1
	_, changed, err := prepareRoutingBatch(t.Context(), batch, 1, 1, routingViewBudget())
	if err != nil || changed == digest || attributes.Wire[2].Value[0] != 0 {
		t.Fatal("changed complete payload kept replay identity or aliased stored attributes", err)
	}
	for _, afi := range []uint16{1, 2} {
		complete := BGPRoutingBatch{Sequence: 2, AFI: afi, SAFI: 1, ObservedAt: batch.ObservedAt, EndOfRIB: true}
		if changes, _, err := prepareRoutingBatch(t.Context(), complete, afi, 1, routingViewBudget()); err != nil || len(changes) != 0 {
			t.Fatal("exclusive family completion was refused", err)
		}
	}
}

func TestBGPRoutingBatchRefusesWholeMalformedOrUnadmittedInput(t *testing.T) {
	for _, change := range []func(*BGPRoutingBatch){
		func(b *BGPRoutingBatch) { b.WireDigest = []byte{1} },
		func(b *BGPRoutingBatch) { b.Sequence = 0 },
		func(b *BGPRoutingBatch) { b.Sequence = math.MaxInt64 },
		func(b *BGPRoutingBatch) { b.AFI = 2 },
		func(b *BGPRoutingBatch) { b.SAFI = 2 },
		func(b *BGPRoutingBatch) { b.ObservedAt = time.Time{} },
		func(b *BGPRoutingBatch) { b.EndOfRIB = true },
		func(b *BGPRoutingBatch) { b.Changes[0].Prefix = netip.MustParsePrefix("192.0.2.1/24") },
		func(b *BGPRoutingBatch) { b.Changes[0].HasPathID = false },
		func(b *BGPRoutingBatch) { b.Changes[0].Segments = nil },
		func(b *BGPRoutingBatch) { b.Changes[0].Segments[0].Kind = 0 },
		func(b *BGPRoutingBatch) { b.Changes[0].Segments[0].Values = nil },
		func(b *BGPRoutingBatch) { b.Changes[0].Attributes.Wire = nil },
		func(b *BGPRoutingBatch) { b.Changes[0].NextHops = nil },
		func(b *BGPRoutingBatch) { b.Changes[0].NextHops[0] = netip.MustParseAddr("fe80::1%eth0") },
		func(b *BGPRoutingBatch) { b.Changes[0].Withdraw = true },
	} {
		batch := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: time.Now(), Changes: []BGPRoutingChange{routingChangeFixture()}}
		change(&batch)
		if prepared, digest, err := prepareRoutingBatch(t.Context(), batch, 1, 1, routingViewBudget()); !errors.Is(err, ErrBGPRoutingBatch) || prepared != nil || digest != ([32]byte{}) {
			t.Fatal("malformed complete routing batch returned a partial result", err)
		}
	}
	batch := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: time.Now(), Changes: []BGPRoutingChange{routingChangeFixture(), routingChangeFixture()}}
	for _, budget := range []BGPRoutingBudget{{}, {MemoryBytes: 3000, WorkUnits: 1 << 20, StateBytes: 1 << 20}, {MemoryBytes: 1 << 20, WorkUnits: 300, StateBytes: 1 << 20}} {
		if prepared, digest, err := prepareRoutingBatch(t.Context(), batch, 1, 1, budget); !errors.Is(err, ErrBGPRoutingBudget) || prepared != nil || digest != ([32]byte{}) {
			t.Fatal("unadmitted complete routing batch returned a partial result", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if prepared, digest, err := prepareRoutingBatch(ctx, batch, 1, 1, routingViewBudget()); !errors.Is(err, context.Canceled) || prepared != nil || digest != ([32]byte{}) {
		t.Fatal("canceled routing batch returned work", err)
	}
}

func TestBGPRoutingHeartbeatRequiresExclusiveFrameAndPositiveServerLease(t *testing.T) {
	heartbeat := BGPRoutingBatch{Sequence: 1, AFI: 2, SAFI: 1, ObservedAt: time.Now(), Heartbeat: true}
	profile := routingViewBudget()
	profile.LeaseDuration = time.Minute
	if changes, digest, err := prepareRoutingBatch(t.Context(), heartbeat, 2, 1, profile); err != nil || len(changes) != 0 || digest == ([32]byte{}) {
		t.Fatal("exclusive routing heartbeat was refused", err)
	}
	if _, _, err := prepareRoutingBatch(t.Context(), heartbeat, 2, 1, routingViewBudget()); !errors.Is(err, ErrBGPRoutingBudget) {
		t.Fatal("heartbeat invented missing operator lease policy", err)
	}
	heartbeat.EndOfRIB = true
	if _, _, err := prepareRoutingBatch(t.Context(), heartbeat, 2, 1, profile); !errors.Is(err, ErrBGPRoutingBatch) {
		t.Fatal("heartbeat manufactured initial synchronization", err)
	}
	heartbeat.EndOfRIB = false
	heartbeat.Changes = []BGPRoutingChange{routingChangeFixture()}
	heartbeat.Changes[0].Prefix = netip.MustParsePrefix("2001:db8::/64")
	if _, _, err := prepareRoutingBatch(t.Context(), heartbeat, 2, 1, profile); !errors.Is(err, ErrBGPRoutingBatch) {
		t.Fatal("heartbeat mixed unadmitted route data", err)
	}
}
