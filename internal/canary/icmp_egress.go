// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/ctlplne/probectl/internal/entity"
)

const (
	ethernetHeaderBytes = 14
	etherTypeIPv4       = 0x0800
	etherTypeIPv6       = 0x86dd
	linuxPacketOutgoing = 4 // Linux PACKET_OUTGOING ABI
)

// ICMPEgress identifies an operator-provisioned interface, source address and
// first-hop Ethernet destination. Provision it locally on the enrolled probe
// agent. Remote test parameters alone do not authorize an egress binding.
type ICMPEgress struct {
	Interface string
	Source    netip.Addr
	PeerMAC   [6]byte
}

// ICMPEgressMeasurement confirms the kernel observed each matching request on
// the configured egress interface with the expected first-hop destination.
// The control plane must still match this to a current authorized handoff
// before attributing observed latency or loss to an upstream.
type ICMPEgressMeasurement struct {
	ICMPEgress
	Transmitted int
}

type icmpEgressWitness interface {
	interfaceIndex() int
	verifiedMeasurement(map[uint64]int, []bool) *ICMPEgressMeasurement
	Close()
}

func icmpInterfaceWriter(conn *icmp.PacketConn, v6 bool, ifindex int, source netip.Addr) func([]byte, net.Addr) (int, error) {
	if v6 {
		control := &ipv6.ControlMessage{IfIndex: ifindex, Src: source.AsSlice()}
		return func(packet []byte, destination net.Addr) (int, error) {
			return conn.IPv6PacketConn().WriteTo(packet, control, destination)
		}
	}
	control := &ipv4.ControlMessage{IfIndex: ifindex, Src: source.AsSlice()}
	return func(packet []byte, destination net.Addr) (int, error) {
		return conn.IPv4PacketConn().WriteTo(packet, control, destination)
	}
}

// NewICMPWithEgress creates a probe for a locally provisioned measurement lane.
// Bound probes use a literal destination and small, bounded request batches.
func NewICMPWithEgress(cfg Config, egress ICMPEgress) (Canary, error) {
	target, err := netip.ParseAddr(cfg.Target)
	if err != nil || !validICMPEgressIP(target) || !validICMPEgressIP(egress.Source) ||
		target.Is4() != egress.Source.Is4() || target == egress.Source ||
		!entity.ValidICMPEgressInterface(egress.Interface) || egress.PeerMAC == [6]byte{} || egress.PeerMAC[0]&1 != 0 {
		return nil, errors.New("icmp: invalid locally provisioned egress binding")
	}
	c, err := newICMP(cfg)
	if err != nil {
		return nil, err
	}
	if c.count > entity.MaxICMPEgressAttempts || c.payload > 1200 {
		return nil, errors.New("icmp: egress witness requires at most 32 requests and 1200 payload bytes")
	}
	c.egress = &egress
	return c, nil
}

func validICMPEgressIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && !ip.Is4In6() && ip.IsGlobalUnicast()
}

func lookupICMPEgressInterface(egress ICMPEgress) (*net.Interface, error) {
	iface, err := net.InterfaceByName(egress.Interface)
	if err != nil {
		return nil, err
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 ||
		len(iface.HardwareAddr) != len(egress.PeerMAC) {
		return nil, errors.New("icmp: egress witness requires an active Ethernet interface")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == egress.Source {
			return iface, nil
		}
	}
	return nil, errors.New("icmp: egress source is not assigned to the interface")
}

func icmpEgressFilter(egress ICMPEgress, target netip.Addr, tokens []byte) ([]bpf.Instruction, int) {
	filter := make([]bpf.Instruction, 0, 64)
	match := func(load bpf.Instruction, value uint32) {
		filter = append(filter, load, bpf.JumpIf{Cond: bpf.JumpEqual, Val: value, SkipTrue: 1}, bpf.RetConstant{})
	}
	address := func(offset uint32, wire []byte) {
		for i := 0; i < len(wire); i += 4 {
			match(bpf.LoadAbsolute{Off: offset, Size: 4}, binary.BigEndian.Uint32(wire[i:i+4]))
			offset += 4
		}
	}
	match(bpf.LoadExtension{Num: bpf.ExtType}, linuxPacketOutgoing)
	address(0, egress.PeerMAC[:4])
	match(bpf.LoadAbsolute{Off: 4, Size: 2}, uint32(binary.BigEndian.Uint16(egress.PeerMAC[4:])))

	// Admit unfragmented IP with the usual fixed headers. Unsupported
	// encapsulations leave the whole measurement without path authority.
	ip := uint32(ethernetHeaderBytes)
	echo := ip + 20
	if target.Is4() {
		match(bpf.LoadAbsolute{Off: 12, Size: 2}, etherTypeIPv4)
		match(bpf.LoadAbsolute{Off: ip, Size: 1}, 0x45)
		match(bpf.LoadAbsolute{Off: ip + 9, Size: 1}, ianaProtoICMP)
		filter = append(filter, bpf.LoadAbsolute{Off: ip + 6, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 0xbfff, SkipTrue: 1}, bpf.RetConstant{})
		address(ip+12, egress.Source.AsSlice())
		address(ip+16, target.AsSlice())
		match(bpf.LoadAbsolute{Off: echo, Size: 2}, 0x0800)
	} else {
		echo = ip + 40
		match(bpf.LoadAbsolute{Off: 12, Size: 2}, etherTypeIPv6)
		match(bpf.LoadAbsolute{Off: ip + 6, Size: 1}, ianaProtoICMPv6)
		address(ip+8, egress.Source.AsSlice())
		address(ip+24, target.AsSlice())
		match(bpf.LoadAbsolute{Off: echo, Size: 2}, 0x8000)
	}
	for i := 0; i < len(tokens)/8; i++ {
		token := tokens[i*8 : (i+1)*8]
		filter = append(filter,
			bpf.LoadAbsolute{Off: echo + 8, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: binary.BigEndian.Uint32(token[:4]), SkipFalse: 5},
			bpf.LoadAbsolute{Off: echo + 12, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: binary.BigEndian.Uint32(token[4:]), SkipFalse: 3},
			bpf.LoadAbsolute{Off: echo + 6, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(i), SkipFalse: 1},
			bpf.RetConstant{Val: echo + 16})
	}
	return append(filter, bpf.RetConstant{}), int(echo)
}
