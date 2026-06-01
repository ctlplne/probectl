package topology

import (
	"testing"
	"time"

	bgpv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/bgp/v1"
	ebpfv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/ebpf/v1"
	"github.com/imfeelingtheagi/netctl/internal/path"
)

func TestFromServiceEdgeAndBGP(t *testing.T) {
	in := FromServiceEdge(&ebpfv1.ServiceEdge{Source: "checkout", Destination: "orders", DestinationPort: 8443, NetworkTransport: "tcp", L7Protocol: "grpc"})
	if in.Source != "checkout" || in.DestPort != 8443 || in.Protocol != "grpc" {
		t.Errorf("FromServiceEdge = %+v", in)
	}
	r := FromBGPEvent(&bgpv1.BGPEvent{Prefix: "192.0.2.0/24", NewOriginAsn: 64500, PeerAsn: 65000, EventType: bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE})
	if r.Prefix != "192.0.2.0/24" || r.OriginASN != 64500 || r.PeerASN != 65000 {
		t.Errorf("FromBGPEvent = %+v", r)
	}
}

func TestFromPath(t *testing.T) {
	p := path.Path{
		Target: "example.com", TargetIP: "93.184.216.34",
		Hops:  []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "10.0.0.1"}}}, {TTL: 2, Nodes: []path.HopNode{{IP: "10.0.0.2"}}}},
		Links: []path.Link{{TTL: 1, From: "10.0.0.1", To: "10.0.0.2"}},
	}
	in := FromPath(p, "agent-1")
	if in.AgentID != "agent-1" || len(in.Hops) != 2 || len(in.Links) != 1 || in.TargetIP != "93.184.216.34" {
		t.Errorf("FromPath = %+v", in)
	}

	// The mapped input builds a graph that traverses agent → target.
	g := NewGraph("t1")
	at := time.Unix(0, 0)
	g.ObservePath(in, at)
	if got := g.Traverse("agent:agent-1", "host:93.184.216.34", at); len(got) == 0 {
		t.Error("expected agent → target path from the mapped fixture")
	}
}
