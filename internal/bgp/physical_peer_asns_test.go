// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"testing"
)

func physicalOpenPairForTest(local, remote uint32, capability bool) []byte {
	open := func(asn uint32) []byte {
		var caps []byte
		if capability {
			caps = binary.BigEndian.AppendUint32([]byte{65, 4}, asn)
		}
		raw := routeOpenForTest(caps, false)
		wire := uint16(asn)
		if asn > 65535 {
			wire = 23456
		}
		binary.BigEndian.PutUint16(raw[20:22], wire)
		return raw
	}
	raw := peerUpFrameForTest(open(local), open(remote), nil)
	binary.BigEndian.PutUint32(raw[32:36], remote)
	return raw
}

func TestPhysicalPeerOpenASNsKeepsBothOriginalASNsAndRefusesPartialIdentity(t *testing.T) {
	budget := PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	for _, pair := range []PhysicalPeerASNs{{Local: 64496, Remote: 4294967295}, {Local: 4294967294, Remote: 64500}, {Local: 64500, Remote: 64501}} {
		for _, capability := range []bool{true, false} {
			if !capability && (pair.Local > 65535 || pair.Remote > 65535) {
				continue
			}
			raw := physicalOpenPairForTest(pair.Local, pair.Remote, capability)
			got, err := PhysicalPeerOpenASNs(t.Context(), raw, budget)
			if err != nil || got != pair {
				t.Fatal("original local/remote ASN changed", got, pair, err)
			}
			fact, err := DecodePhysicalPeerSession(t.Context(), raw, budget)
			if err != nil || fact.PeerASN != pair.Remote {
				t.Fatal("session and OPEN identity diverged", err)
			}
		}
	}
	for _, name := range []string{"pseudo peer", "wire ASN contradiction", "header ASN contradiction", "truncated", "down", "no admission", "canceled"} {
		t.Run(name, func(t *testing.T) {
			raw := physicalOpenPairForTest(64496, 4294967295, true)
			profile := budget
			ctx := t.Context()
			switch name {
			case "pseudo peer":
				raw[6] = 3
			case "wire ASN contradiction":
				binary.BigEndian.PutUint16(raw[68+20:68+22], 64500)
			case "header ASN contradiction":
				binary.BigEndian.PutUint32(raw[32:36], 64500)
			case "truncated":
				raw = raw[:len(raw)-1]
			case "down":
				raw = peerDownFrameForTest(4, nil, false)
			case "no admission":
				profile = PeerMessageBudget{MemoryBytes: 1, WorkUnits: 1}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if got, err := PhysicalPeerOpenASNs(ctx, raw, profile); err == nil || got != (PhysicalPeerASNs{}) {
				t.Fatal("incomplete source exposed AS identity", got, err)
			}
		})
	}
}
