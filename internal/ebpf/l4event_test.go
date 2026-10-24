// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestL4EventCLayoutSize(t *testing.T) {
	if got := binary.Size(l4eventC{}); got != 96 {
		t.Fatalf("l4eventC binary size = %d, want 96 to match bpf/l4flow.bpf.c", got)
	}
}

// TestL4EventOrientsByRole is the ING-24 decode contract: the kernel tuple is
// local-first, and the role decides which side is the client. A server socket
// (an inbound connection) must come out client -> server, keyed on the LISTEN
// port, with the owning process on the server endpoint.
func TestL4EventOrientsByRole(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "tenant-a"
	local := netip.MustParseAddr("10.0.0.5").As4()
	peer := netip.MustParseAddr("10.0.0.9").As4()
	ev := func(role uint8, sport, dport uint16) l4eventC {
		e := l4eventC{PID: 777, Sport: sport, Dport: dport, Family: l4FamilyIPv4,
			NewState: l4TCPStateEstablished, Role: role, Sock: 0xffff000012345678, BornNS: 42}
		copy(e.Comm[:], "nginx")
		copy(e.Saddr[:], local[:])
		copy(e.Daddr[:], peer[:])
		return e
	}

	srv := ev(roleServer, 443, 51000).toFlow(cfg)
	if srv.Source.Address != "10.0.0.9" || srv.Source.Port != 51000 || srv.Source.PID != 0 || srv.Source.Process != "" {
		t.Fatalf("server-side source = %+v, want the remote client 10.0.0.9:51000 with no process", srv.Source)
	}
	if srv.Destination.Address != "10.0.0.5" || srv.Destination.Port != 443 || srv.Destination.PID != 777 || srv.Destination.Process != "nginx" {
		t.Fatalf("server-side destination = %+v, want the local server 10.0.0.5:443 owned by nginx(777)", srv.Destination)
	}
	if srv.Direction != DirectionIngress || srv.LocalEndpoint().Process != "nginx" {
		t.Fatalf("server-side direction/local = %q/%+v, want ingress with nginx local", srv.Direction, srv.LocalEndpoint())
	}

	cli := ev(roleClient, 51000, 443).toFlow(cfg)
	if cli.Source.Port != 51000 || cli.Source.Process != "nginx" || cli.Destination.Port != 443 || cli.Direction != DirectionEgress {
		t.Fatalf("client-side flow = %+v, want local source -> peer:443 egress", cli)
	}

	unk := ev(roleUnknown, 51000, 443).toFlow(cfg)
	if unk.Direction != "" || unk.Source.Address != "10.0.0.5" {
		t.Fatalf("unknown-role flow = %+v, want local-first with no direction claim", unk)
	}
	if srv.connKey == 0 || srv.connKey == connIdentity(0xffff000012345678, 43) {
		t.Fatalf("connection identity must be non-zero and change with the birth time")
	}
}

// TestL4EventUnmapsDualStackIPv4 keeps an IPv4 client on a dual-stack listener
// on the same IPv4 edge its own socket reports.
func TestL4EventUnmapsDualStackIPv4(t *testing.T) {
	e := l4eventC{Family: l4FamilyIPv6, Role: roleServer, Sport: 80, Dport: 40000}
	s := netip.MustParseAddr("::ffff:10.0.0.5").As16()
	d := netip.MustParseAddr("::ffff:10.0.0.9").As16()
	copy(e.Saddr[:], s[:])
	copy(e.Daddr[:], d[:])
	f := e.toFlow(Default())
	if f.NetworkType != NetworkIPv4 || f.Source.Address != "10.0.0.9" || f.Destination.Address != "10.0.0.5" {
		t.Fatalf("v4-mapped flow = %+v, want the plain IPv4 tuple", f)
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
