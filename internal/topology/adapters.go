package topology

import (
	bgpv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/bgp/v1"
	ebpfv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/ebpf/v1"
	"github.com/imfeelingtheagi/netctl/internal/path"
)

// FromPath maps a discovered Path (S10) to a PathInput, so a consumer of the
// path plane feeds the graph from live telemetry.
func FromPath(p path.Path, agent string) PathInput {
	in := PathInput{AgentID: agent, Target: p.Target, TargetIP: p.TargetIP}
	for _, h := range p.Hops {
		for _, n := range h.Nodes {
			if n.IP != "" {
				in.Hops = append(in.Hops, n.IP)
			}
		}
	}
	for _, l := range p.Links {
		in.Links = append(in.Links, Link{From: l.From, To: l.To})
	}
	return in
}

// FromServiceEdge maps an eBPF ServiceEdge (S20) to a ServiceEdgeInput.
func FromServiceEdge(e *ebpfv1.ServiceEdge) ServiceEdgeInput {
	return ServiceEdgeInput{
		Source:      e.GetSource(),
		Destination: e.GetDestination(),
		DestPort:    e.GetDestinationPort(),
		Transport:   e.GetNetworkTransport(),
		Protocol:    e.GetL7Protocol(),
	}
}

// FromBGPEvent maps a BGP routing-security event (S14) to a RoutingInput.
func FromBGPEvent(e *bgpv1.BGPEvent) RoutingInput {
	return RoutingInput{
		Prefix:    e.GetPrefix(),
		OriginASN: e.GetNewOriginAsn(),
		PeerASN:   e.GetPeerAsn(),
		EventType: e.GetEventType().String(),
	}
}
