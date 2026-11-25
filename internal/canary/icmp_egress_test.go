// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
)

func TestICMPEgressFilterAdmitsOnlyExactUpstreamRequests(t *testing.T) {
	for _, lane := range []struct {
		name, source, target string
	}{
		{"ipv4", "192.0.2.5", "203.0.113.90"},
		{"ipv6", "2001:db8:1::5", "2001:db8:3::90"},
	} {
		t.Run(lane.name, func(t *testing.T) {
			testICMPEgressFilter(t, netip.MustParseAddr(lane.source), netip.MustParseAddr(lane.target))
		})
	}
}

func testICMPEgressFilter(t *testing.T, source, target netip.Addr) {
	t.Helper()
	egress := ICMPEgress{Interface: "tenant-owned-lab", Source: source, PeerMAC: [6]byte{2, 1, 2, 3, 4, 5}}
	tokens := []byte("a1234567b1234567")
	program, echo := icmpEgressFilter(egress, target, tokens)
	if _, err := bpf.Assemble(program); err != nil {
		t.Fatal(err)
	}
	// Packet direction is a Linux skb extension. The Go interpreter can
	// exercise the rest of the installed filter with an Ethernet frame.
	if program[0] != (bpf.LoadExtension{Num: bpf.ExtType}) ||
		program[1] != (bpf.JumpIf{Cond: bpf.JumpEqual, Val: linuxPacketOutgoing, SkipTrue: 1}) ||
		program[2] != (bpf.RetConstant{}) {
		t.Fatal("egress filter does not first require a kernel outgoing packet")
	}
	vm, err := bpf.NewVM(program[3:])
	if err != nil {
		t.Fatal(err)
	}
	ip := ethernetHeaderBytes
	frame := make([]byte, echo+8+56)
	copy(frame, egress.PeerMAC[:])
	sourceOffset, targetOffset := ip+12, ip+16
	if target.Is4() {
		binary.BigEndian.PutUint16(frame[12:], etherTypeIPv4)
		frame[ip], frame[ip+9] = 0x45, ianaProtoICMP
	} else {
		binary.BigEndian.PutUint16(frame[12:], etherTypeIPv6)
		frame[ip], frame[ip+6] = 0x60, ianaProtoICMPv6
		sourceOffset, targetOffset = ip+8, ip+24
	}
	copy(frame[sourceOffset:], source.AsSlice())
	copy(frame[targetOffset:], target.AsSlice())
	for sequence := 0; sequence < len(tokens)/8; sequence++ {
		request, err := buildEcho(target.Is6(), 675, sequence, tokens[sequence*8:(sequence+1)*8], 56)
		if err != nil {
			t.Fatal(err)
		}
		copy(frame[echo:], request)
		if captured, err := vm.Run(frame); err != nil || captured != echo+16 {
			t.Fatalf("request %d captured %d bytes, err %v", sequence, captured, err)
		}
	}
	for _, offset := range []int{5, sourceOffset, targetOffset, echo, echo + 7, echo + 8, echo + 15} {
		modified := bytes.Clone(frame)
		modified[offset] ^= 1
		if captured, err := vm.Run(modified); err != nil || captured != 0 {
			t.Fatalf("changed byte %d captured %d bytes, err %v", offset, captured, err)
		}
	}
	if captured, err := vm.Run(frame[:echo+15]); err != nil || captured != 0 {
		t.Fatalf("truncated request captured %d bytes, err %v", captured, err)
	}
}
