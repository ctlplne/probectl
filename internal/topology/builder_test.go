// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package topology

import (
	"testing"
	"time"
)

func TestObservePathBuildsGraph(t *testing.T) {
	g := NewGraph("t1")
	at := time.Unix(100, 0)
	g.ObservePath(PathInput{
		AgentID: "agent-1", Target: "example.com", TargetIP: "93.184.216.34",
		Hops:  []string{"10.0.0.1", "10.0.0.2"},
		Links: []Link{{"10.0.0.1", "10.0.0.2"}},
	}, at)

	// agent + host(target) + 2 hops
	if g.nodeCount() != 4 {
		t.Errorf("nodes = %d, want 4", g.nodeCount())
	}
	if p := g.Traverse("agent:agent-1", "host:93.184.216.34", at); len(p) == 0 {
		t.Error("expected an agent → target path, got none")
	}
}

func TestObserveServiceEdgeAndRouting(t *testing.T) {
	g := NewGraph("t1")
	at := time.Unix(0, 0)
	g.ObserveServiceEdge(ServiceEdgeInput{Source: "checkout", Destination: "orders", DestPort: 8443, Transport: "tcp", Protocol: "http1"}, at)
	g.ObserveRouting(RoutingInput{Prefix: "192.0.2.0/24", OriginASN: 64500, PeerASN: 65000, EventType: "origin_change"}, at)

	if g.nodeCount() != 4 { // service:checkout, service:orders, as:64500, prefix:192.0.2.0/24
		t.Errorf("nodes = %d, want 4", g.nodeCount())
	}
	if g.edgeCount() != 2 { // flow + routing
		t.Errorf("edges = %d, want 2", g.edgeCount())
	}
	for _, e := range g.Latest().Edges {
		if e.Kind == EdgeFlow && e.Attributes["destination.port"] != "8443" {
			t.Errorf("flow edge attributes = %v", e.Attributes)
		}
	}
}
