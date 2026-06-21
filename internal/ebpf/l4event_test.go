// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestL4EventCLayoutSize(t *testing.T) {
	if got := binary.Size(l4eventC{}); got != 80 {
		t.Fatalf("l4eventC binary size = %d, want 80 to match bpf/l4flow.bpf.c", got)
	}
}

func TestL4EventCToFlowIPv6WithCounters(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "tenant-a"
	cfg.Host = "node-a"
	src := netip.MustParseAddr("2001:db8::10")
	dst := netip.MustParseAddr("2001:db8::20")
	e := l4eventC{
		Bytes:    4096,
		Packets:  12,
		PID:      4242,
		Sport:    51515,
		Dport:    443,
		Family:   l4FamilyIPv6,
		NewState: l4TCPStateClose,
	}
	copy(e.Comm[:], "curl")
	src16 := src.As16()
	dst16 := dst.As16()
	copy(e.Saddr[:], src16[:])
	copy(e.Daddr[:], dst16[:])

	f := e.toFlow(cfg)
	if f.TenantID != "tenant-a" || f.AgentID != "node-a" || f.Host != "node-a" {
		t.Fatalf("identity not stamped from config: %+v", f)
	}
	if f.NetworkType != NetworkIPv6 || f.Source.Address != src.String() || f.Destination.Address != dst.String() {
		t.Fatalf("IPv6 addresses not decoded: %+v", f)
	}
	if f.Bytes != 4096 || f.Packets != 12 {
		t.Fatalf("counters = bytes=%d packets=%d, want 4096/12", f.Bytes, f.Packets)
	}
	if f.State != StateClose || f.Source.Process != "curl" {
		t.Fatalf("state/process not decoded: %+v", f)
	}
}

func TestL4CloseEventUpdatesVolumeWithoutDoubleCountingConnection(t *testing.T) {
	m := NewServiceMap()
	at := time.Unix(1700, 0)
	opened := Flow{
		TenantID:    "t",
		Source:      Endpoint{Address: "10.0.0.10"},
		Destination: Endpoint{Address: "10.0.0.20", Port: 443},
		Transport:   TransportTCP,
		State:       StateEstablished,
		Observed:    at,
	}
	closed := opened
	closed.State = StateClose
	closed.Bytes = 8192
	closed.Packets = 24
	closed.Observed = at.Add(time.Second)

	m.Observe(opened)
	m.Observe(closed)
	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap))
	}
	edge := snap[0]
	if edge.Connections != 1 {
		t.Fatalf("connections = %d, want 1 after open+close for the same socket", edge.Connections)
	}
	if edge.Bytes != 8192 || edge.Packets != 24 {
		t.Fatalf("volume = bytes=%d packets=%d, want 8192/24", edge.Bytes, edge.Packets)
	}
	if !edge.LastSeen.Equal(closed.Observed) {
		t.Fatalf("last_seen = %v, want close timestamp %v", edge.LastSeen, closed.Observed)
	}
}
