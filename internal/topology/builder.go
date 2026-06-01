package topology

import (
	"strconv"
	"time"
)

// Link is an observed hop-to-hop adjacency (responder IPs).
type Link struct{ From, To string }

// PathInput is a discovered path (S10) ready to fold into the graph.
type PathInput struct {
	AgentID  string
	Target   string // path target (hostname / label)
	TargetIP string
	Hops     []string // responder IPs (ECMP branches included)
	Links    []Link   // observed adjacencies between responder IPs
}

// ServiceEdgeInput is an eBPF service edge (S20).
type ServiceEdgeInput struct {
	Source      string
	Destination string
	DestPort    uint32
	Transport   string
	Protocol    string // L7 protocol (optional)
}

// RoutingInput is a BGP routing observation (S14).
type RoutingInput struct {
	Prefix    string
	OriginASN uint32
	PeerASN   uint32
	EventType string
}

func hopID(ip string) string      { return "hop:" + ip }
func hostID(ip string) string     { return "host:" + ip }
func agentID(id string) string    { return "agent:" + id }
func serviceID(id string) string  { return "service:" + id }
func prefixID(cidr string) string { return "prefix:" + cidr }
func asID(asn uint32) string      { return "as:" + strconv.FormatUint(uint64(asn), 10) }

// ObservePath folds a discovered path into the graph: an agent node, hop nodes,
// hop→hop path edges, and the agent→first-hop / last-hop→target framing.
func (g *Graph) ObservePath(in PathInput, at time.Time) {
	if in.AgentID != "" {
		g.UpsertNode(Node{ID: agentID(in.AgentID), Kind: NodeAgent, Label: in.AgentID}, at)
	}
	var target string
	if in.TargetIP != "" {
		target = hostID(in.TargetIP)
		g.UpsertNode(Node{ID: target, Kind: NodeHost, Label: in.Target}, at)
	}
	for _, ip := range in.Hops {
		if ip != "" {
			g.UpsertNode(Node{ID: hopID(ip), Kind: NodeHop, Label: ip}, at)
		}
	}
	for _, l := range in.Links {
		if l.From == "" || l.To == "" {
			continue
		}
		g.UpsertNode(Node{ID: hopID(l.From), Kind: NodeHop, Label: l.From}, at)
		g.UpsertNode(Node{ID: hopID(l.To), Kind: NodeHop, Label: l.To}, at)
		g.UpsertEdge(Edge{From: hopID(l.From), To: hopID(l.To), Kind: EdgePath}, at)
	}
	if in.AgentID != "" {
		if first := firstNonEmpty(in.Hops); first != "" {
			g.UpsertEdge(Edge{From: agentID(in.AgentID), To: hopID(first), Kind: EdgePath}, at)
		}
	}
	if target != "" {
		if last := lastNonEmpty(in.Hops); last != "" && hopID(last) != target {
			g.UpsertEdge(Edge{From: hopID(last), To: target, Kind: EdgePath}, at)
		}
	}
}

// ObserveServiceEdge folds an eBPF service edge into the graph.
func (g *Graph) ObserveServiceEdge(in ServiceEdgeInput, at time.Time) {
	if in.Source == "" || in.Destination == "" {
		return
	}
	src, dst := serviceID(in.Source), serviceID(in.Destination)
	g.UpsertNode(Node{ID: src, Kind: NodeService, Label: in.Source}, at)
	g.UpsertNode(Node{ID: dst, Kind: NodeService, Label: in.Destination}, at)
	attrs := map[string]string{}
	if in.DestPort != 0 {
		attrs["destination.port"] = strconv.FormatUint(uint64(in.DestPort), 10)
	}
	if in.Transport != "" {
		attrs["network.transport"] = in.Transport
	}
	if in.Protocol != "" {
		attrs["network.protocol.name"] = in.Protocol
	}
	g.UpsertEdge(Edge{From: src, To: dst, Kind: EdgeFlow, Label: in.Protocol, Attributes: attrs}, at)
}

// ObserveRouting folds a BGP routing observation (origin AS → prefix) into the graph.
func (g *Graph) ObserveRouting(in RoutingInput, at time.Time) {
	if in.Prefix == "" || in.OriginASN == 0 {
		return
	}
	as, pfx := asID(in.OriginASN), prefixID(in.Prefix)
	g.UpsertNode(Node{ID: as, Kind: NodeAS, Label: "AS" + strconv.FormatUint(uint64(in.OriginASN), 10)}, at)
	g.UpsertNode(Node{ID: pfx, Kind: NodePrefix, Label: in.Prefix}, at)
	attrs := map[string]string{}
	if in.EventType != "" {
		attrs["netctl.bgp.event_type"] = in.EventType
	}
	if in.PeerASN != 0 {
		attrs["netctl.bgp.peer_asn"] = strconv.FormatUint(uint64(in.PeerASN), 10)
	}
	g.UpsertEdge(Edge{From: as, To: pfx, Kind: EdgeRouting, Attributes: attrs}, at)
}

func firstNonEmpty(s []string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func lastNonEmpty(s []string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != "" {
			return s[i]
		}
	}
	return ""
}
