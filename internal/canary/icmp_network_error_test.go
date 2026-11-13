// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/ctlplne/probectl/internal/crypto"
)

func networkErrorPacketForTest(t *testing.T, v6 bool, quote []byte, code int) ([]byte, *icmp.Message) {
	t.Helper()
	var kind icmp.Type = ipv4.ICMPTypeDestinationUnreachable
	protocol := ianaProtoICMP
	if v6 {
		kind = ipv6.ICMPTypeDestinationUnreachable
		protocol = ianaProtoICMPv6
	}
	var pseudo []byte
	if v6 {
		pseudo = icmp.IPv6PseudoHeader(net.ParseIP("2001:db8:2::1"), net.ParseIP("2001:db8:100::1"))
	}
	raw, err := (&icmp.Message{Type: kind, Code: code, Body: &icmp.DstUnreach{Data: quote}}).Marshal(pseudo)
	if err != nil {
		t.Fatal(err)
	}
	message, err := icmp.ParseMessage(protocol, raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, message
}

func quotedProbeForTest(t *testing.T, v6 bool, target netip.Addr, token []byte, payload int) []byte {
	t.Helper()
	echo, err := buildEcho(v6, 17, 0, token, payload)
	if err != nil {
		t.Fatal(err)
	}
	if v6 {
		quote := make([]byte, 40)
		quote[0], quote[6] = 0x60, ianaProtoICMPv6
		source := netip.MustParseAddr("2001:db8:100::1").As16()
		copy(quote[8:24], source[:])
		binary.BigEndian.PutUint16(quote[4:6], uint16(len(echo)))
		address := target.As16()
		copy(quote[24:40], address[:])
		return append(quote, echo...)
	}
	quote := make([]byte, 20)
	quote[0], quote[9] = 0x45, ianaProtoICMP
	binary.BigEndian.PutUint16(quote[2:4], uint16(len(echo)+20))
	address := target.As4()
	copy(quote[16:20], address[:])
	return append(quote, echo...)
}

func TestICMPNetworkErrorsRequireWholeMatchingProbeChallenge(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, name := range []string{"whole", "short quote", "wrong challenge", "wrong destination", "wrong sequence", "wrong ID", "unwritten", "corrupt padding", "extended IPv6", "nonfirst fragment"} {
			t.Run(map[bool]string{false: "IPv4/", true: "IPv6/"}[v6]+name, func(t *testing.T) {
				target := netip.MustParseAddr("198.51.100.7")
				responder := net.ParseIP("192.0.2.254")
				if v6 {
					target = netip.MustParseAddr("2001:db8:1::7")
					responder = net.ParseIP("2001:db8:2::1")
				}
				token := []byte{1, 2, 3, 4, 5, 6, 7, 8}
				// Cross the wire sequence wrap: the challenge identifies the
				// full configured population rather than the low16 sequence.
				const sequence = 65536
				state := icmpProbeState{raw: true, v6: v6, id: 17, target: target, payload: icmpEchoPayload(token, 56), challenges: map[uint64]int{binary.BigEndian.Uint64(token): sequence}, written: make([]bool, sequence+1), networkErrors: make([]*ICMPNetworkError, sequence+1)}
				state.written[sequence] = true
				quote := quotedProbeForTest(t, v6, target, token, 56)
				offset := 20
				if v6 {
					offset = 40
				}
				switch name {
				case "short quote":
					quote = quote[:offset+8]
				case "wrong challenge":
					quote[offset+8] ^= 255
				case "wrong destination":
					if v6 {
						quote[39] ^= 1
					} else {
						quote[19] ^= 1
					}
				case "wrong sequence":
					quote[offset+7] = 1
				case "wrong ID":
					quote[offset+5] = 18
				case "unwritten":
					state.written[sequence] = false
				case "corrupt padding":
					quote[len(quote)-1] ^= 1
				case "extended IPv6":
					if v6 {
						extended := append([]byte(nil), quote[:40]...)
						extended[6] = 0
						binary.BigEndian.PutUint16(extended[4:6], uint16(len(quote)-40+8))
						extended = append(extended, 58, 0, 0, 0, 0, 0, 0, 0)
						quote = append(extended, quote[40:]...)
					}
				case "nonfirst fragment":
					if v6 {
						fragment := append([]byte(nil), quote[:40]...)
						fragment[6] = 44
						binary.BigEndian.PutUint16(fragment[4:6], uint16(len(quote)-40+8))
						fragment = append(fragment, 58, 0, 0, 8, 0, 0, 0, 1)
						quote = append(fragment, quote[40:]...)
					} else {
						quote[7] = 1
					}
				}
				raw, message := networkErrorPacketForTest(t, v6, quote, 0)
				at := time.Now().UTC()
				if !state.retainNetworkError(message, raw, &net.IPAddr{IP: responder}, at) {
					t.Fatal("network error was not dispatched")
				}
				valid := name == "whole" || name == "extended IPv6"
				fact := state.networkErrors[sequence]
				if !valid {
					if fact != nil {
						t.Fatal("unmatched or incomplete quote authored an error fact")
					}
					return
				}
				var digest [32]byte
				copy(digest[:], crypto.Hash(raw))
				if fact == nil || fact.Sequence != sequence || fact.Responder != responder.String() || fact.PacketDigest != digest || !fact.ReceivedAt.Equal(at) || fact.Conflicting {
					t.Fatal("original matched outcome or whole packet digest changed")
				}
				clear(raw)
				if fact.PacketDigest != digest {
					t.Fatal("outcome borrowed mutable receive storage")
				}
				other := &net.IPAddr{IP: net.ParseIP("192.0.2.253")}
				if v6 {
					other.IP = net.ParseIP("2001:db8:2::2")
				}
				secondRaw, secondMessage := networkErrorPacketForTest(t, v6, quote, 0)
				if v6 {
					var err error
					secondRaw, err = secondMessage.Marshal(icmp.IPv6PseudoHeader(other.IP, net.ParseIP("2001:db8:100::1")))
					if err != nil {
						t.Fatal(err)
					}
				}
				state.retainNetworkError(secondMessage, secondRaw, other, at.Add(time.Microsecond))
				if !fact.Conflicting {
					t.Fatal("different terminal responder silently selected a winner")
				}
			})
		}
	}
}
