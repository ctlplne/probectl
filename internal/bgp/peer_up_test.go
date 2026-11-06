// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func peerUpFrameForTest(sent, received []byte, info []PeerUpInformation) []byte {
	raw := make([]byte, bmpCommonHeaderLen+bmpPeerHeaderLen+20)
	raw[0], raw[5] = 3, 3
	header := raw[bmpCommonHeaderLen : bmpCommonHeaderLen+bmpPeerHeaderLen]
	copy(header[22:26], []byte{198, 51, 100, 2})
	binary.BigEndian.PutUint32(header[26:30], 4294967295)
	copy(header[30:34], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint32(header[34:38], 10)
	binary.BigEndian.PutUint32(header[38:42], 20)
	copy(raw[60:64], []byte{192, 0, 2, 10})
	binary.BigEndian.PutUint16(raw[64:66], 179)
	binary.BigEndian.PutUint16(raw[66:68], 20000)
	raw = append(raw, sent...)
	raw = append(raw, received...)
	for _, value := range info {
		raw = binary.BigEndian.AppendUint16(raw, value.Type)
		raw = binary.BigEndian.AppendUint16(raw, uint16(len(value.Value)))
		raw = append(raw, value.Value...)
	}
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	return raw
}

func TestBMPPeerUpKeepsWholeSourceMetadataAndOwnedCopies(t *testing.T) {
	open := routeOpenForTest([]byte{65, 4, 255, 255, 255, 255, 69, 4, 0, 1, 1, 3}, true)
	info := []PeerUpInformation{{3, []byte("vrf-東京")}, {3, []byte("edge-🛰")}, {60000, bytes.Repeat([]byte{0, 255, 1}, 21845)}}
	for _, name := range []string{"ipv4", "ipv6", "loc-rib"} {
		t.Run(name, func(t *testing.T) {
			raw := peerUpFrameForTest(open, open, info)
			wantAddress := netip.MustParseAddr("192.0.2.10")
			wantView, wantPort, filtered := BMPAdjRIBInPrePolicy, uint16(179), false
			switch name {
			case "ipv6":
				raw[7] = 0x80
				remote := netip.MustParseAddr("2001:db8::2").As16()
				local := netip.MustParseAddr("2001:db8::10").As16()
				copy(raw[16:32], remote[:])
				copy(raw[48:64], local[:])
				wantAddress = netip.AddrFrom16(local)
			case "loc-rib":
				raw[6], raw[7] = 3, 0x80
				clear(raw[16:32])
				clear(raw[48:68])
				wantAddress, wantView, wantPort, filtered = netip.Addr{}, BMPLocRIB, 0, true
			}
			out, err := ParseBMPPeerUp(context.Background(), raw, PeerUpBudget{128 * int64(len(raw)), 4 * int64(len(raw))})
			if err != nil || out.Header.View != wantView || out.Header.Filtered != filtered || !out.Header.TimestampKnown || out.Header.PeerASN != 4294967295 || out.LocalAddress != wantAddress || out.LocalPort != wantPort || !bytes.Equal(out.SentOpen, open) || !bytes.Equal(out.ReceivedOpen, open) || !reflect.DeepEqual(out.Information, info) {
				t.Fatal("complete BMP Peer Up lost route-view, OPEN or ordered information", err, len(out.Information))
			}
			if name == "loc-rib" && (out.Header.PeerAddress.IsValid() || out.RemotePort != 0) {
				t.Fatal("Loc-RIB fabricated a remote peer or transport port")
			}
			clear(raw)
			if !bytes.Equal(out.SentOpen, open) || !bytes.Equal(out.ReceivedOpen, open) || !reflect.DeepEqual(out.Information, info) {
				t.Fatal("input mutation changed owned Peer Up source metadata")
			}
			out.Information[0].Value[0] = 0
			if string(info[0].Value) != "vrf-東京" || out.Information[1].Value[0] != 'e' {
				t.Fatal("Peer Up information values shared mutable ownership")
			}
		})
	}
}

type peerUpCancelContext struct {
	context.Context
	checks int
}

func (c *peerUpCancelContext) Err() error {
	c.checks++
	if c.checks >= 4 {
		return context.Canceled
	}
	return nil
}

func TestBMPPeerUpRefusesIncompleteTailAdmissionAndCancellation(t *testing.T) {
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 69, 4, 0, 1, 1, 3}, false)
	good := peerUpFrameForTest(open, open, []PeerUpInformation{{3, []byte("one")}, {3, []byte("two")}})
	budget := PeerUpBudget{128 * int64(len(good)+20), 4 * int64(len(good)+20)}
	variants := [][]byte{nil, append([]byte(nil), good[:5]...), append([]byte(nil), good[:68]...), append([]byte(nil), good[:68+len(open)]...), append(append([]byte(nil), good...), 0)}
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 2 },
		func(raw []byte) { raw[5] = 4 },
		func(raw []byte) { raw[7] = 0; raw[48] = 1 },
		func(raw []byte) { raw[68+len(open)] = 0 },
		func(raw []byte) { raw[len(raw)-4] = 255 },
		func(raw []byte) { raw[6] = 3; clear(raw[16:32]) }, // Invalid local port/address for Loc-RIB.
	} {
		raw := append([]byte(nil), good...)
		mutate(raw)
		variants = append(variants, raw)
	}
	for _, raw := range variants {
		if len(raw) >= 5 {
			binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
		}
		out, err := ParseBMPPeerUp(context.Background(), raw, budget)
		if !errors.Is(err, ErrBMPPeerUp) || !reflect.DeepEqual(out, PeerUp{}) {
			t.Fatal("incomplete Peer Up returned partial source metadata", err)
		}
	}
	for _, limited := range []PeerUpBudget{{0, 10000}, {10000, 0}, {128*int64(len(good)) - 1, 4 * int64(len(good))}, {128 * int64(len(good)), 4*int64(len(good)) - 1}} {
		out, err := ParseBMPPeerUp(context.Background(), good, limited)
		if !errors.Is(err, ErrBMPPeerUpBudget) || !reflect.DeepEqual(out, PeerUp{}) {
			t.Fatal("unadmitted Peer Up allocated visible source metadata", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{canceled, &peerUpCancelContext{Context: context.Background()}} {
		out, err := ParseBMPPeerUp(ctx, good, budget)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, PeerUp{}) {
			t.Fatal("canceled Peer Up retained a partial session", err)
		}
	}
}
