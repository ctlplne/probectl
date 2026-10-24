// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

const (
	l4FamilyIPv4 = uint16(2)
	l4FamilyIPv6 = uint16(10)

	l4TCPStateEstablished = uint8(1)
	l4TCPStateClose       = uint8(7)
)

// Connection roles, mirroring PROBECTL_ROLE_* in bpf/conn_role.h (ING-24).
const (
	roleUnknown = uint8(0)
	roleClient  = uint8(1)
	roleServer  = uint8(2)
)

// l4eventC mirrors struct l4_event in bpf/l4flow.bpf.c (96 bytes,
// little-endian). Keep field order and explicit padding in sync. Saddr/Sport
// are the LOCAL side and Daddr/Dport the peer; Role says which is the client.
type l4eventC struct {
	Bytes    uint64
	Packets  uint64
	Sock     uint64 // kernel socket identity (agent-internal, never published)
	BornNS   uint64 // connection birth from the in-kernel role cache (0 = unknown)
	PID      uint32 // owning process (0 = unknown)
	Sport    uint16
	Dport    uint16
	Family   uint16
	NewState uint8
	Role     uint8
	Comm     [16]byte
	Saddr    [16]byte
	Daddr    [16]byte
	Pad2     [4]byte
}

// toFlow orients the local-first kernel tuple as client -> server (ING-24).
// A client socket's local side is the source; a server socket's local side is
// the DESTINATION, so the edge is keyed on the listening port and the owning
// process sits on the server endpoint. A socket of unknown role keeps the
// legacy local-first orientation without a direction claim.
func (e l4eventC) toFlow(cfg *Config) Flow {
	src, dst, networkType := e.addresses()
	local := Endpoint{Address: src, Port: uint32(e.Sport), PID: e.PID, Process: nullTerm(e.Comm[:])}
	peer := Endpoint{Address: dst, Port: uint32(e.Dport)}
	f := Flow{
		TenantID:    cfg.TenantID,
		AgentID:     cfg.identity(),
		Host:        cfg.Host,
		Transport:   TransportTCP,
		NetworkType: networkType,
		Bytes:       e.Bytes,
		Packets:     e.Packets,
		State:       e.state(),
		role:        e.Role,
		connKey:     connIdentity(e.Sock, e.BornNS),
	}
	switch e.Role {
	case roleServer:
		f.Source, f.Destination, f.Direction = peer, local, DirectionIngress
	case roleClient:
		f.Source, f.Destination, f.Direction = local, peer, DirectionEgress
	default:
		f.Source, f.Destination = local, peer
	}
	return f
}

// connIdentity names one connection inside the agent: the kernel socket plus
// its birth time, so a socket address the kernel reuses for a later
// connection is a different identity. Zero sock = no identity.
func connIdentity(sock, bornNS uint64) uint64 {
	if sock == 0 {
		return 0
	}
	return sock ^ (bornNS * 0x9e3779b97f4a7c15)
}

func decodeL4FlowSample(sample []byte, cfg *Config) (Flow, error) {
	var e l4eventC
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &e); err != nil {
		return Flow{}, err
	}
	return e.toFlow(cfg), nil
}

func (e l4eventC) state() string {
	if e.NewState == l4TCPStateClose {
		return StateClose
	}
	return StateEstablished
}

func (e l4eventC) addresses() (string, string, string) {
	switch e.Family {
	case l4FamilyIPv4:
		var src, dst [4]byte
		copy(src[:], e.Saddr[:4])
		copy(dst[:], e.Daddr[:4])
		return netip.AddrFrom4(src).String(), netip.AddrFrom4(dst).String(), NetworkIPv4
	case l4FamilyIPv6:
		var src, dst [16]byte
		copy(src[:], e.Saddr[:])
		copy(dst[:], e.Daddr[:])
		s, d := netip.AddrFrom16(src), netip.AddrFrom16(dst)
		if s.Is4In6() && d.Is4In6() {
			// An IPv4 client on a dual-stack listener: report the IPv4 tuple,
			// so the edge matches the one the client's own socket produces.
			return s.Unmap().String(), d.Unmap().String(), NetworkIPv4
		}
		return s.String(), d.String(), NetworkIPv6
	default:
		return "", "", ""
	}
}

func nullTerm(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
