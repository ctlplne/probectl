// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"net/netip"
	"testing"
)

func TestRoutingStreamProtocolSelectorOnlyRefusesCanonicalSelection(t *testing.T) {
	source := BGPRoutingSource{routingSelection: &routingSourceSelection{Binding: routingSourceBinding{Distinguisher: "ffffffffffffffff", BGPIdentifier: "0.0.0.0"}}}
	peer := BGPRoutingPeer{Type: 3, Distinguisher: [8]byte{255, 255, 255, 255, 255, 255, 255, 255}, BGPIdentifier: netip.MustParseAddr("0.0.0.0")}
	if err := routingStreamSelectorMatches(source, &peer); err != nil {
		t.Fatal("exact opaque mapped selector refused", err)
	}
	for _, change := range []func(*BGPRoutingPeer){
		func(p *BGPRoutingPeer) { p.Distinguisher[7]-- },
		func(p *BGPRoutingPeer) { p.BGPIdentifier = netip.MustParseAddr("192.0.2.1") },
		func(p *BGPRoutingPeer) { p.Type = 0 },
		func(p *BGPRoutingPeer) { p.BGPIdentifier = netip.MustParseAddr("2001:db8::1") },
	} {
		other := peer
		change(&other)
		if err := routingStreamSelectorMatches(source, &other); err == nil {
			t.Fatal("unbound stream selector reached known generation reset or decoder")
		}
	}
	if err := routingStreamSelectorMatches(BGPRoutingSource{}, &peer); err == nil {
		t.Fatal("legacy global source accepted a non-global selector")
	}
	if err := routingStreamSelectorMatches(source, nil); err != nil {
		t.Fatal("authenticated payload-free generation reset refused", err)
	}
}
