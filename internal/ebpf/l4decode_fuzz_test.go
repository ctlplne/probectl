// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzL4DecodeFlowSample covers the first userspace boundary for raw L4 eBPF
// ring-buffer samples. The live source adds recover/drop accounting around this
// helper; the helper itself must decode arbitrary bytes without panics or
// cross-tenant identity drift.
func FuzzL4DecodeFlowSample(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3})
	f.Add(rawL4FuzzEvent(l4FamilyIPv4, netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.20")))
	f.Add(rawL4FuzzEvent(l4FamilyIPv6, netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8::20")))

	f.Fuzz(func(t *testing.T, sample []byte) {
		cfg := Default()
		cfg.TenantID = "tenant-fuzz"
		cfg.Host = "host-fuzz"

		flow, err := decodeL4FlowSample(sample, cfg)
		if err != nil {
			return
		}
		if flow.TenantID != cfg.TenantID || flow.AgentID != cfg.Host || flow.Host != cfg.Host {
			t.Fatalf("flow identity = tenant=%q agent=%q host=%q", flow.TenantID, flow.AgentID, flow.Host)
		}
		if flow.Transport != TransportTCP || flow.Direction != DirectionEgress {
			t.Fatalf("flow transport/direction = %q/%q", flow.Transport, flow.Direction)
		}
		if flow.State != StateEstablished && flow.State != StateClose {
			t.Fatalf("flow state = %q", flow.State)
		}
	})
}

func rawL4FuzzEvent(family uint16, src, dst netip.Addr) []byte {
	e := l4eventC{
		Bytes:    128,
		Packets:  4,
		PID:      4242,
		Sport:    51515,
		Dport:    443,
		Family:   family,
		NewState: l4TCPStateEstablished,
	}
	copy(e.Comm[:], "curl")
	if family == l4FamilyIPv4 {
		src4 := src.As4()
		dst4 := dst.As4()
		copy(e.Saddr[:4], src4[:])
		copy(e.Daddr[:4], dst4[:])
	} else {
		src16 := src.As16()
		dst16 := dst.As16()
		copy(e.Saddr[:], src16[:])
		copy(e.Daddr[:], dst16[:])
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, e)
	return buf.Bytes()
}
