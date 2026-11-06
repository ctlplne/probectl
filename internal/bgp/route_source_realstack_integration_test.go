// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
)

// This source proof reads the actual pinned FRR daemon's loopback-published
// BMP feed. It does not claim an authenticated control-plane RPC, stored RIB
// or flow join; those remain separately required original item proofs.
func TestBMPLocRIBRealRouterKeepsCompletePeerAndFamilyMarkers(t *testing.T) {
	lab := startRoutingLabNamed(t, "probectl-qa-beta-current-rib-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	link := addRoleRouterLink(t, lab, "transit", "edge", 234, edgeASN, entity.InterfaceRoleTransit)
	lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN), "-c", "bmp targets probectl", "-c", "bmp monitor ipv4 unicast loc-rib", "-c", "bmp monitor ipv6 unicast loc-rib", "-c", "end")
	conn, err := net.DialTimeout("tcp", lab.bmpAddr(t, "rtr-a"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(30 * time.Second)
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	peers := map[string]bgp.PeerUp{}
	markers := map[bgp.RouteFamily]bool{}
	announced := map[uint16]bool{}
	unknownClocks := 0
	key := func(h bgp.BMPRouteViewHeader) string {
		return fmt.Sprintf("%d/%x/%s/%d/%s", h.PeerType, h.Distinguisher, h.PeerAddress, h.PeerASN, h.BGPIdentifier)
	}
	for !markers[bgp.RouteFamily{AFI: 1, SAFI: 1}] || !markers[bgp.RouteFamily{AFI: 2, SAFI: 1}] || !announced[1] || !announced[2] {
		var common [6]byte
		if _, err := io.ReadFull(conn, common[:]); err != nil {
			t.Fatalf("real Loc-RIB source missing complete dual-stack dump: markers=%v announced=%v: %v", markers, announced, err)
		}
		size := int64(binary.BigEndian.Uint32(common[1:5]))
		if common[0] != 3 || size < 6 || size > 1<<20 {
			t.Fatal("pinned FRR emitted malformed/unadmitted BMP framing", size)
		}
		raw := make([]byte, int(size))
		copy(raw, common[:])
		if _, err := io.ReadFull(conn, raw[6:]); err != nil {
			t.Fatal(err)
		}
		if common[5] != 0 && common[5] != 3 {
			continue
		}
		if len(raw) < 48 {
			t.Fatal("pinned FRR omitted its complete per-peer header")
		}
		h, err := bgp.ParseBMPRouteViewHeader(raw[6:48])
		if err != nil {
			t.Fatal(err)
		}
		if h.View != bgp.BMPLocRIB {
			continue
		}
		if common[5] == 3 {
			peer, err := bgp.SourcePeerUpForTest(t.Context(), raw, bgp.PeerMessageBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20})
			if err != nil {
				t.Fatal("actual Loc-RIB Peer Up refused", err)
			}
			peers[key(h)] = peer
			continue
		}
		peer, present := peers[key(h)]
		if !present {
			t.Fatal("actual Loc-RIB update preceded matching complete Peer Up")
		}
		frame, err := bgp.SourceRouteForTest(t.Context(), raw, peer, bgp.UpdateFrameBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20})
		if err != nil {
			t.Fatal("actual Loc-RIB UPDATE/source identity refused", err)
		}
		if frame.Header.Filtered || frame.Header.View != bgp.BMPLocRIB {
			t.Fatal("pinned complete Loc-RIB source became a filtered or adjacent view")
		}
		if !frame.Header.TimestampKnown {
			unknownClocks++
		}
		if frame.Update.HasEndOfRIB {
			markers[frame.Update.EndOfRIB] = true
		}
		if len(frame.Update.ReachableIPv4) > 0 {
			prefixes, err := bgp.SourceLegacyPrefixesForTest(t.Context(), frame, peer)
			if err != nil {
				t.Fatal("actual Loc-RIB legacy NLRI refused", err)
			}
			for _, prefix := range prefixes {
				if prefix.Prefix.String() == prefixA {
					announced[1] = true
				}
			}
		}
		for _, attr := range frame.Update.Attributes {
			if attr.Type != 14 {
				continue
			}
			reach, err := bgp.SourceMPReachForTest(t.Context(), attr.Value, frame, peer)
			if err != nil {
				t.Fatal("actual Loc-RIB multiprotocol reach refused", err)
			}
			for _, prefix := range reach.Prefixes {
				if reach.Family.AFI == 1 && prefix.Prefix.String() == prefixA || reach.Family.AFI == 2 && prefix.Prefix.String() == link.prefix6 {
					announced[reach.Family.AFI] = true
				}
			}
		}
	}
	t.Logf("real-integration: pinned FRR Loc-RIB complete Peer Up, both-family announcements/EOR, explicit unknown wire clocks=%d; source framing only, authenticated RPC/store/flow proof owed", unknownClocks)
}
