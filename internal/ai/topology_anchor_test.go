// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/topology"
)

// TestRCATopologyWalksFromAnAddressToItsOrigin is DPR-299's regression: an
// RCA question that names an address (the planner's anchor for it is
// "service:<ip>") found no topology evidence unless an eBPF service carried
// that exact name, so a host traced by the path plane, the managed device
// answering on it and the hijacked prefix holding it never reached the
// answer. The topology step must now anchor on every node the tenant's graph
// keys by that address and on the prefixes whose block holds it, and still
// nothing of another tenant's graph that shares the address.
func TestRCATopologyWalksFromAnAddressToItsOrigin(t *testing.T) {
	store := topology.NewIndexedStore()
	at := time.Unix(1_700_000_000, 0)
	for tenant, f := range map[string]struct {
		sysName, chassis, eth0, prefix string
		origin                         uint32
	}{
		"tenant-a": {"acme-core-sw1", "02:42:ac:11:00:a1", "172.17.0.2", "127.0.0.0/24", 65021},
		"tenant-b": {"globex-edge-r1", "02:42:ac:11:00:b2", "172.17.0.3", "198.51.100.0/24", 64501},
	} {
		g, err := store.ForTenant(tenant)
		if err != nil {
			t.Fatal(err)
		}
		g.ObservePath(topology.PathInput{AgentID: "control", Target: "127.0.0.1", TargetIP: "127.0.0.1", Hops: []string{"127.0.0.1"}}, at)
		g.ObserveDevice(topology.DeviceInput{Address: "127.0.0.1", Name: f.sysName, InterfaceIPs: []string{"127.0.0.1", f.eth0}}, at)
		g.ReplacePhysicalAdjacencies(topology.PhysicalAdjacencySnapshot{SourceAgent: "dev-" + tenant, LocalAddress: "127.0.0.1",
			Adjacencies: []topology.PhysicalAdjacencyInput{{LocalAddress: "127.0.0.1", LocalName: f.sysName, LocalPort: "eth0",
				RemoteIdentity: f.chassis, RemoteName: "nbr-" + tenant, RemotePort: "Gi0/1", Protocol: "lldp"}}}, at)
		g.ObserveRouting(topology.RoutingInput{Prefix: f.prefix, OriginASN: f.origin}, at)
		g.ObserveRouting(topology.RoutingInput{Prefix: "10.0.0.0/8", OriginASN: 64999}, at) // holds nothing asked
	}
	e := NewEngine(WithTopology(NewTopologySource(store)))

	var topo *Query
	for _, q := range (HeuristicPlanner{}).Plan(Question{Text: "Why is the service at 127.0.0.1 failing?"}) {
		if q.Domain == DomainTopology {
			topo = &q
		}
	}
	if topo == nil {
		t.Fatal("the planner emitted no topology step for an address question")
	}
	res, err := e.Query(context.Background(), principal("tenant-a", PermTopologyRead), *topo)
	if err != nil {
		t.Fatal(err)
	}
	type edge struct{ node, neighbor, kind string }
	got := map[edge]bool{}
	nodes := map[string]string{}
	for _, row := range res.Rows {
		node, neighbor := rowString(row, "node"), rowString(row, "neighbor")
		if neighbor == "" {
			nodes[node] = rowString(row, "label")
			continue
		}
		got[edge{node, neighbor, rowString(row, "kind")}] = true
	}
	for id, label := range map[string]string{"host:127.0.0.1": "127.0.0.1", "hop:127.0.0.1": "127.0.0.1",
		"device:127.0.0.1": "acme-core-sw1", "prefix:127.0.0.0/24": "127.0.0.0/24"} {
		if nodes[id] != label {
			t.Errorf("topology evidence for 127.0.0.1 has node %s = %q, want %q (nodes %v)", id, nodes[id], label, nodes)
		}
	}
	for _, want := range []edge{
		{"hop:127.0.0.1", "agent:control", "path"},
		{"host:127.0.0.1", "hop:127.0.0.1", "path"},
		{"device:127.0.0.1", "hop:172.17.0.2", "device"},
		{"device:127.0.0.1", "device:lldp:02:42:ac:11:00:a1", "physical"},
		{"prefix:127.0.0.0/24", "as:65021", "routing"},
	} {
		if !got[want] {
			t.Errorf("topology evidence for 127.0.0.1 misses %+v (got %v)", want, got)
		}
	}
	for _, row := range res.Rows {
		for _, v := range row {
			s, _ := v.(string)
			for _, foreign := range []string{"globex", "02:42:ac:11:00:b2", "172.17.0.3", "198.51.100.0/24", "64501", "10.0.0.0/8"} {
				if strings.Contains(s, foreign) {
					t.Errorf("tenant-a's topology evidence holds %q: %+v", foreign, row)
				}
			}
		}
	}

	// An explicit node subject stays exactly that node.
	explicit := HeuristicPlanner{}.Plan(Question{Text: "neighbors?", Subject: map[string]string{"node": "hop:127.0.0.1", "target": "127.0.0.1"}})
	idx := slices.IndexFunc(explicit, func(q Query) bool { return q.Domain == DomainTopology })
	if idx < 0 {
		t.Fatal("no topology step for an explicit node subject")
	}
	res, err = e.Query(context.Background(), principal("tenant-a", PermTopologyRead), explicit[idx])
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range res.Rows {
		if rowString(row, "node") != "hop:127.0.0.1" {
			t.Errorf("an explicit node subject anchored on %q too: %+v", rowString(row, "node"), row)
		}
	}
}

// TestRCATopologyContextAloneIsNotARootCause: with DPR-299 an address
// question gathers topology context even when no signal names the address.
// The builtin synthesizer must not then present a node's existence as the
// root cause ("Most likely root cause: topology node 127.0.0.1"): the answer
// is insufficient evidence, with the context as cited findings.
func TestRCATopologyContextAloneIsNotARootCause(t *testing.T) {
	store := topology.NewIndexedStore()
	g, err := store.ForTenant("tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	g.ObserveDevice(topology.DeviceInput{Address: "127.0.0.1", Name: "globex-edge-r1", InterfaceIPs: []string{"127.0.0.1"}}, time.Now())
	a := NewAnalyzer(NewEngine(WithTopology(NewTopologySource(store))))
	ans, err := a.Analyze(context.Background(), principal("tenant-b", PermTopologyRead), Question{Text: "Why is the service at 127.0.0.1 failing?"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Evidence) == 0 {
		t.Fatal("the address question gathered no topology context")
	}
	if !ans.InsufficientEvidence || ans.RootCauseGrounded || ans.Confidence != ConfidenceLow ||
		!strings.HasPrefix(ans.RootCause, "Insufficient evidence: only topology context") {
		t.Errorf("topology context alone answered %q (insufficient %v, grounded %v, %s), want insufficient evidence",
			ans.RootCause, ans.InsufficientEvidence, ans.RootCauseGrounded, ans.Confidence)
	}
	if len(ans.Findings) == 0 || !strings.HasPrefix(ans.Findings[0].Statement, "Topology context:") || len(ans.Findings[0].Citations) != 1 {
		t.Errorf("findings = %+v, want the topology context as cited findings", ans.Findings)
	}
}
