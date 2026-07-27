// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package topology

import (
	"strconv"
	"strings"
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

// DeviceInput is a managed-device observation (S39 telemetry, S43): the device
// itself, plus the interface IPs it carries when the telemetry exposes them —
// each links the device to the path-plane hop with that IP (the
// services↔paths↔DEVICES↔prefixes dependency chain).
type DeviceInput struct {
	Address      string // management address (the device's identity)
	Name         string // sysName / gNMI target (label)
	InterfaceIPs []string
	Source       string // snmp | gnmi | another local device producer
	AgentID      string
	IfIndex      uint32
	IfName       string
}

// PhysicalAdjacencyInput is direct LLDP/CDP evidence. It is not a subnet
// discovery or inferred FDB/ARP relationship.
type PhysicalAdjacencyInput struct {
	LocalAddress   string
	LocalName      string
	LocalPort      string
	RemoteAddress  string
	RemoteIdentity string
	RemoteName     string
	RemotePort     string
	Protocol       string
	Confidence     string
	SourceAgent    string
	FreshUntil     time.Time
}

// PhysicalAdjacencySnapshot is one authoritative, successful LLDP/CDP poll
// for a tenant-bound agent and local device. Adjacencies omitted from the
// snapshot are no longer current for this source, but remain queryable at
// their historical observation times.
type PhysicalAdjacencySnapshot struct {
	SourceAgent  string
	LocalAddress string
	Adjacencies  []PhysicalAdjacencyInput
}

func hopID(ip string) string      { return "hop:" + ip }
func hostID(ip string) string     { return "host:" + ip }
func agentID(id string) string    { return "agent:" + id }
func serviceID(id string) string  { return "service:" + id }
func prefixID(cidr string) string { return "prefix:" + cidr }
func asID(asn uint32) string      { return "as:" + strconv.FormatUint(uint64(asn), 10) }
func deviceID(addr string) string { return "device:" + addr }

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

// ObserveDevice folds a managed device into the graph: a device node, and a
// device→hop edge per interface IP (linking the device plane onto the path
// plane). Telemetry that exposes no interface IPs still yields the device
// node — the missing linkage is a reportable coverage gap, not silent.
func (g *Graph) ObserveDevice(in DeviceInput, at time.Time) {
	if in.Address == "" {
		return
	}
	// Capture competing source assertions before the graph's display-label
	// upsert can replace the previous value. This is read-only evidence; it
	// never chooses a winner or rewrites an entity.
	observeDeviceIdentity(g, in, at)
	dev := deviceID(in.Address)
	label := in.Name
	if label == "" {
		label = in.Address
	}
	g.UpsertNode(Node{ID: dev, Kind: NodeDevice, Label: label,
		Attributes: map[string]string{"probectl.device.address": in.Address}}, at)
	for _, ip := range in.InterfaceIPs {
		if ip == "" {
			continue
		}
		g.UpsertNode(Node{ID: hopID(ip), Kind: NodeHop, Label: ip}, at)
		g.UpsertEdge(Edge{From: dev, To: hopID(ip), Kind: EdgeDevice}, at)
	}
}

// ObservePhysicalAdjacency folds one directly observed LLDP/CDP neighbor into
// the temporal graph. The remote identity prefers a management address, then
// the protocol's chassis/device identifier; no guessed IP or merge occurs.
func (g *Graph) ObservePhysicalAdjacency(in PhysicalAdjacencyInput, at time.Time) {
	localNode, remoteNode, edge, ok := physicalAdjacencyElements(in)
	if !ok {
		return
	}
	g.UpsertNode(localNode, at)
	g.UpsertNode(remoteNode, at)
	g.UpsertEdge(edge, at)
}

func physicalAdjacencyElements(in PhysicalAdjacencyInput) (Node, Node, Edge, bool) {
	if in.LocalAddress == "" || (in.RemoteAddress == "" && in.RemoteIdentity == "") {
		return Node{}, Node{}, Edge{}, false
	}
	local := deviceID(in.LocalAddress)
	localLabel := firstNonEmpty([]string{in.LocalName, in.LocalAddress})
	localNode := Node{ID: local, Kind: NodeDevice, Label: localLabel,
		Attributes: map[string]string{"probectl.device.address": in.LocalAddress}}
	remoteKey := in.RemoteAddress
	if remoteKey == "" {
		remoteKey = in.Protocol + ":" + in.RemoteIdentity
	}
	remote := deviceID(remoteKey)
	remoteLabel := firstNonEmpty([]string{in.RemoteName, in.RemoteAddress, in.RemoteIdentity})
	attrs := map[string]string{"probectl.device.identity": in.RemoteIdentity}
	if in.RemoteAddress != "" {
		attrs["probectl.device.address"] = in.RemoteAddress
	}
	remoteNode := Node{ID: remote, Kind: NodeDevice, Label: remoteLabel, Attributes: attrs}
	label := strings.Trim(strings.Join([]string{in.LocalPort, in.RemotePort}, " ↔ "), " ↔")
	edgeAttrs := map[string]string{
		"probectl.device.neighbor.protocol":   in.Protocol,
		"probectl.device.neighbor.confidence": in.Confidence,
		"probectl.device.local_port":          in.LocalPort,
		"probectl.device.remote_port":         in.RemotePort,
	}
	if in.SourceAgent != "" {
		edgeAttrs["probectl.agent.id"] = in.SourceAgent
	}
	if !in.FreshUntil.IsZero() {
		edgeAttrs["probectl.device.neighbor.fresh_until"] = in.FreshUntil.UTC().Format(time.RFC3339Nano)
	}
	edge := Edge{
		From: local, To: remote, Kind: EdgePhysical, Label: label,
		Attributes: edgeAttrs,
	}
	edge.ID = EdgeID(edge.From, edge.Kind, edge.To)
	return localNode, remoteNode, edge, true
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
		attrs["probectl.bgp.event_type"] = in.EventType
	}
	if in.PeerASN != 0 {
		attrs["probectl.bgp.peer_asn"] = strconv.FormatUint(uint64(in.PeerASN), 10)
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
