// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

// l4eventC mirrors struct l4_event in bpf/l4flow.bpf.c (80 bytes,
// little-endian). Keep field order and explicit padding in sync.
type l4eventC struct {
	Bytes    uint64
	Packets  uint64
	PID      uint32
	Sport    uint16
	Dport    uint16
	Family   uint16
	NewState uint8
	Pad      uint8
	Comm     [16]byte
	Saddr    [16]byte
	Daddr    [16]byte
	Pad2     [4]byte
}

func (e l4eventC) toFlow(cfg *Config) Flow {
	src, dst, networkType := e.addresses()
	return Flow{
		TenantID:    cfg.TenantID,
		AgentID:     cfg.Host,
		Host:        cfg.Host,
		Source:      Endpoint{Address: src, Port: uint32(e.Sport), PID: e.PID, Process: nullTerm(e.Comm[:])},
		Destination: Endpoint{Address: dst, Port: uint32(e.Dport)},
		Transport:   TransportTCP,
		NetworkType: networkType,
		Bytes:       e.Bytes,
		Packets:     e.Packets,
		Direction:   DirectionEgress,
		State:       e.state(),
	}
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
		return netip.AddrFrom16(src).String(), netip.AddrFrom16(dst).String(), NetworkIPv6
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
