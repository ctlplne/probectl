// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package topology_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// snmpdBase is the base of the lab's SNMP agents (the F18 receipt's): Alpine
// 3.22.6, pinned by digest, running net-snmp 5.9.4's snmpd from that
// release's own package repository.
const snmpdBase = "alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

// pollInterval is the device agents' poll cadence: the shortest the
// collection profiles accept as an override.
const pollInterval = 15 * time.Second

// The lab's routing plan (the F13 receipt's). A's block is the loopback /24
// its devices and path target sit in; B's is from the documentation range.
const (
	collectorASN = 64511 // the lab route collector's peer
	upstreamASN  = 65010 // "the internet": the upstream on every path
	labCollector = "lab-rrc"
	sharedAddr   = "127.0.0.1"
)

// TestTopologyGraphRealStack is the real-stack receipt for the live topology
// graph (F40): an MSP's two tenants each get a graph built from their own
// real telemetry — SNMP device inventory and LLDP adjacencies, control-plane
// path discovery, BGP origin events — and each reads, changes, simulates and
// walks it through the public API, the CLI and the rendered Topology page,
// seeing nothing of the other's.
//
// No eBPF input feeds this graph: the eBPF service map reverses the
// direction of inbound flows (ING-24, open), so the receipt stays on the
// planes whose edges it can state exactly. NetFlow/IPFIX flow records are
// not a topology input in the product (flow edges are the eBPF service
// map's), so the flow plane is not exercised either.
//
// The stack is the shipped control plane on the four-store profile
// (shipped.Start): a fresh PostgreSQL database behind the least-privilege
// serve login, Kafka with strict tenant lanes, ClickHouse with the reader
// credential, Prometheus as the TSDB, TLS on every listener, Dex as the IdP
// (production session auth in Chromium) and an MSP license. A is pooled, B
// hybrid. The graph is the shipped in-RAM indexed engine fed by the shipped
// topology consumer.
//
// The inputs, each produced by the shipped collector an earlier receipt
// proves, all on the SAME address so a lost tenant scope shows:
//
//   - Device (F18): one net-snmp snmpd container per tenant, polled by the
//     tenant's shipped probectl-device-agent at 127.0.0.1 on a loopback port.
//     The devices differ in sysName, in the LLDP neighbor each reports (its
//     chassis id, name and port) and in eth0's address on the docker bridge.
//     The device plane yields device:127.0.0.1 -device-> hop:127.0.0.1 (lo)
//     and -device-> hop:<eth0> from ipAddrTable, and the LLDP-MIB rows yield
//     device:127.0.0.1 -physical-> device:lldp:<chassis>.
//
//   - Path (F3): each tenant traces 127.0.0.1 from the control plane (A
//     through the API, B through the CLI): agent:control -path->
//     hop:127.0.0.1 -path-> host:127.0.0.1.
//
//   - BGP (F6/F13): each tenant's shipped analyzer sidecar reads the lab
//     collector's MRT with its own watch config and publishes on its own
//     lane. A's 127.0.0.0/24 is hijacked by AS65021, B's 198.51.100.0/24
//     leaks through AS64666: as:65021 -routing-> prefix:127.0.0.0/24 for A,
//     as:64501 -routing-> prefix:198.51.100.0/24 for B.
//
//     1. Each tenant's graph is exactly its own nodes and edges, with the
//     source plane (edge kind) and direction each input implies, on
//     GET /v1/topology and `probectl topology show`; the reverse of every
//     edge is absent. Each plane lands in one tenant only: B's graph holds no
//     path node until B traces, and no routing edge until B's analyzer runs.
//     2. What-if, through POST /v1/topology/whatif and `probectl topology
//     whatif`: failing hop:127.0.0.1 breaks the control plane's path to
//     host:127.0.0.1 (the impacted test, by agent and target) and
//     disconnects exactly the tenant's own downstream nodes (its device, its
//     eth0 hop, its LLDP neighbor); failing its origin AS impacts exactly its
//     prefix. A node of the other tenant's graph is unknown (404 / non-zero
//     exit).
//     3. The incident walks the graph: each tenant's BGP fault opens one
//     incident whose prefix and origin AS are nodes of the tenant's graph,
//     joined by a routing edge. RCA through POST /v1/ai/ask and `probectl ai
//     ask` asks why 127.0.0.1 fails: the topology evidence walks the tenant's
//     own graph from the address to the device answering on it, its eth0 hop
//     and LLDP neighbor and, for A, to the hijacked prefix holding it and the
//     hijacker AS that originates it (DPR-299); every topology evidence item
//     is a node of the tenant's graph. B's prefix question walks to its
//     prefix's origin.
//     4. The rendered Topology page shows each tenant its own graph; selecting
//     hop 127.0.0.1 and simulating its failure shows the tenant's own broken
//     path and disconnected nodes and nothing of the other's.
//     5. Live: A's device starts reporting a different LLDP neighbor. Within
//     two polls A's live graph holds the new adjacency and neither the old
//     edge nor the neighbor only it evidenced, on the API, the CLI and the
//     rendered page; ?at= a moment before the change still shows the old
//     adjacency (the versioned graph); B's graph is untouched.
//     6. Everything each tenant was shown is byte-searched for the other
//     tenant's identifiers.
func TestTopologyGraphRealStack(t *testing.T) {
	python := analyzerPython(t)
	lab := startSNMPLab(t)
	st := shipped.Start(t, shipped.Options{Name: "topology", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-topology.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)

	A := &topoTenant{slug: "topo-acme-" + run, name: "Topology Acme", model: "pooled", admin: "ada@acme.example",
		profile: "topology-rich", sysName: "acme-core-sw1", credential: "acme-core-ro", community: "acme-topo-community-" + run,
		neighbor:  lldpNeighbor{name: "acme-dist-sw2", port: "Gi0/48", chassis: "02:42:ac:11:00:a1"},
		next:      lldpNeighbor{name: "acme-dist-sw3", port: "Gi0/47", chassis: "02:42:ac:11:00:a3"},
		prefix:    "127.0.0.0/24",
		watch:     map[string]any{"prefix": "127.0.0.0/24", "expected_origins": []int{64500}},
		baseline:  []uint32{upstreamASN, 64500},
		changed:   []uint32{upstreamASN, 65021},
		origin:    65021,
		incident:  []string{"bgp.possible_hijack", "bgp.origin_change"},
		question2: "Why is 127.0.0.0/24 originated by AS65021?"}
	B := &topoTenant{slug: "topo-globex-" + run, name: "Topology Globex", model: "hybrid", admin: "bob@globex.example",
		profile: "standard", sysName: "globex-edge-r1", credential: "globex-edge-ro", community: "globex-topo-community-" + run,
		neighbor:  lldpNeighbor{name: "globex-core-r9", port: "xe-0/0/1", chassis: "02:42:ac:11:00:b2"},
		prefix:    "198.51.100.0/24",
		watch:     map[string]any{"prefix": "198.51.100.0/24", "expected_origins": []int{64501}, "no_transit": []int{64666}},
		baseline:  []uint32{upstreamASN, 64501},
		changed:   []uint32{upstreamASN, 64666, 64501},
		origin:    64501,
		incident:  []string{"bgp.possible_leak"},
		question2: "Why is 198.51.100.0/24 routing through AS64666?"}
	tenants := []*topoTenant{A, B}
	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("topo%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "topology.read", "agent.write", "metrics.read", "events.read",
			"entities.read", "incident.read", "ai.query", "test.read", "test.write", "test.allow_private")
		tn.device = lab.startDevice(t, tn)
	}

	// The device plane: A registers through the API, B through the CLI.
	A.registerDeviceAPI(t, st)
	B.registerDeviceCLI(t, st)
	for _, tn := range tenants {
		tn.startDeviceAgent(t, st)
	}
	for _, tn := range tenants {
		tn.awaitGraph(t, st, "its device, interface hops and LLDP neighbor", 150*time.Second, func(g graph) bool {
			return g.hasAll(tn.deviceEdges())
		})
	}
	beforeChange := time.Now()
	for _, tn := range tenants {
		g := tn.topologyAPI(t, st, "")
		for _, id := range []string{"agent:control", "host:" + sharedAddr} {
			if _, ok := g.node(id); ok {
				t.Errorf("GET /v1/topology as %s holds %s before any path was traced", tn.slug, id)
			}
		}
		if n := g.count("routing"); n != 0 {
			t.Errorf("GET /v1/topology as %s holds %d routing edges before any BGP event", tn.slug, n)
		}
	}

	// The path plane: A traces through the API; B's graph must not move.
	for _, tn := range tenants {
		tn.createPathTest(t, st)
	}
	A.discoverAPI(t, st)
	A.awaitGraph(t, st, "its traced path", 30*time.Second, func(g graph) bool { return g.hasAll(pathEdges()) })
	if g := B.topologyAPI(t, st, ""); g.hasAny(pathEdges()) {
		t.Errorf("A's path discovery landed in B's graph: %s", g.describe())
	}
	B.discoverCLI(t, st)
	B.awaitGraph(t, st, "its traced path", 30*time.Second, func(g graph) bool { return g.hasAll(pathEdges()) })

	// The BGP plane: A's hijack, then B's leak, each on its own lane.
	A.setupBGPAPI(t, st)
	B.setupBGPCLI(t, st)
	A.runAnalyzer(t, st, python)
	A.awaitGraph(t, st, "its hijacked prefix's origin", 60*time.Second, func(g graph) bool { return g.hasAll(A.routingEdges()) })
	if g := B.topologyAPI(t, st, ""); g.count("routing") != 0 {
		t.Errorf("A's BGP event landed in B's graph: %s", g.describe())
	}
	B.runAnalyzer(t, st, python)
	B.awaitGraph(t, st, "its leaked prefix's origin", 60*time.Second, func(g graph) bool { return g.hasAll(B.routingEdges()) })

	// 1. Each tenant's graph is exactly its own, on the API and the CLI.
	for _, tn := range tenants {
		for surface, g := range map[string]graph{
			"GET /v1/topology":       tn.topologyAPI(t, st, ""),
			"probectl topology show": tn.topologyCLI(t, st, ""),
		} {
			tn.checkGraph(t, surface, g, tn.neighbor)
		}
	}

	// 2. What-if.
	for _, tn := range tenants {
		tn.checkWhatIf(t, st, tn.other(A, B))
	}

	// 3. The incident walks the tenant's graph.
	for _, tn := range tenants {
		tn.awaitIncident(t, st)
		tn.checkIncidentInGraph(t, st)
		tn.checkRCA(t, st)
	}

	// 4. The rendered Topology page and its what-if overlay.
	for _, tn := range tenants {
		tn.renderTopology(t, st, tn.other(A, B))
	}

	// 5. Live: A's device reports a different LLDP neighbor. The versioned
	// graph is a ledger of sightings (an element is valid between its first
	// and last observation), so the old adjacency is first re-polled at least
	// once after beforeChange: the ?at= read below then falls inside it.
	if wait := time.Until(beforeChange.Add(pollInterval + 5*time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	A.device.setNeighbor(t, A, A.next)
	A.awaitGraph(t, st, "its new LLDP neighbor", 3*pollInterval+30*time.Second, func(g graph) bool {
		_, oldEdge := g.edge("device:"+sharedAddr, "physical", A.neighbor.nodeID())
		_, newEdge := g.edge("device:"+sharedAddr, "physical", A.next.nodeID())
		return newEdge && !oldEdge
	})
	for surface, g := range map[string]graph{
		"GET /v1/topology":       A.topologyAPI(t, st, ""),
		"probectl topology show": A.topologyCLI(t, st, ""),
	} {
		A.checkGraph(t, surface+" after the neighbor change", g, A.next)
	}
	at := beforeChange.Truncate(time.Second).Add(time.Second).UTC().Format(time.RFC3339)
	for surface, g := range map[string]graph{
		"GET /v1/topology?at=":              A.topologyAPI(t, st, at),
		"probectl topology show --query at": A.topologyCLI(t, st, at),
	} {
		if _, ok := g.edge("device:"+sharedAddr, "physical", A.neighbor.nodeID()); !ok {
			t.Errorf("%s%s as %s has no %s adjacency: the graph as it was before the change is lost: %s", surface, at, A.slug, A.neighbor.name, g.describe())
		}
		if _, ok := g.node(A.next.nodeID()); ok {
			t.Errorf("%s%s as %s already holds %s, first seen after that time", surface, at, A.slug, A.next.name)
		}
	}
	B.checkGraph(t, "GET /v1/topology after A's neighbor change", B.topologyAPI(t, st, ""), B.neighbor)
	A.renderLive(t, st, B)

	// 6. Nothing of the other tenant's, anywhere either was shown.
	for _, tn := range tenants {
		tn.checkNothingOf(t, tn.other(A, B))
	}
}

// --- the tenants ---

type lldpNeighbor struct{ name, port, chassis string }

// nodeID is the graph node of a neighbor known only by its LLDP chassis id
// (the lab rows carry no management address).
func (n lldpNeighbor) nodeID() string { return "device:lldp:" + n.chassis }

type topoTenant struct {
	slug, name, model, admin string
	mark, id, cookie, token  string
	profile, sysName         string
	credential, community    string
	neighbor, next           lldpNeighbor
	prefix                   string
	watch                    map[string]any
	baseline, changed        []uint32
	origin                   uint32
	incident                 []string
	question2                string
	device                   *snmpDevice
	collectorID, agentLog    string
	hint                     map[string]any
	testID, testName         string
	bgpSource, bgpLane       string
	incidentID               string
	seen                     [][]byte
	mu                       sync.Mutex
}

func (tn *topoTenant) other(a, b *topoTenant) *topoTenant {
	if tn == a {
		return b
	}
	return a
}

func (tn *topoTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

func (tn *topoTenant) keep(raw []byte) {
	tn.mu.Lock()
	tn.seen = append(tn.seen, append([]byte(nil), raw...))
	tn.mu.Unlock()
}

// identifiers are the strings that are this tenant's alone: anything another
// tenant is shown that holds one of them crossed the tenant boundary.
func (tn *topoTenant) identifiers() []string {
	out := []string{tn.id, tn.slug, tn.mark, tn.sysName, tn.neighbor.name, tn.neighbor.chassis, tn.neighbor.port,
		"hop:" + tn.device.ip, "prefix:" + tn.prefix, tn.prefix, "as:" + strconv.Itoa(int(tn.origin)),
		tn.collectorID, tn.bgpSource, tn.testID, tn.incidentID}
	if tn.next.name != "" {
		out = append(out, tn.next.name, tn.next.chassis, tn.next.port)
	}
	return slices.DeleteFunc(out, func(s string) bool { return s == "" })
}

// foreignIdentifiers are other's identifiers this tenant must never be
// shown, less any that is part of one of its own (172.17.0.2 inside
// 172.17.0.20), which a byte search cannot tell apart.
func (tn *topoTenant) foreignIdentifiers(other *topoTenant) []string {
	own := tn.identifiers()
	return slices.DeleteFunc(other.identifiers(), func(id string) bool {
		return slices.ContainsFunc(own, func(o string) bool { return strings.Contains(o, id) })
	})
}

func (tn *topoTenant) do(t *testing.T, st *shipped.Stack, method, route string, body, out any, want int) []byte {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, method, route, body)
	tn.keep(raw)
	if code != want || (out != nil && json.Unmarshal(raw, out) != nil) {
		t.Fatalf("%s %s as %s = %d (want %d): %.500s", method, route, tn.slug, code, want, raw)
	}
	return raw
}

func (tn *topoTenant) cli(t *testing.T, st *shipped.Stack, out any, args ...string) {
	t.Helper()
	stdout, stderr, code := st.CLI(tn.env(), args...)
	tn.keep([]byte(stdout + stderr))
	if code != 0 {
		t.Fatalf("probectl %s as %s: exit %d: %s%s", strings.Join(args, " "), tn.slug, code, stderr, stdout)
	}
	if out != nil {
		if err := json.Unmarshal([]byte(stdout), out); err != nil {
			t.Fatalf("probectl %s as %s: decode %.300q: %v", strings.Join(args, " "), tn.slug, stdout, err)
		}
	}
}

// --- the graph as the API and the CLI serve it ---

type vizNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type vizEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type graph struct {
	TopologyRunning bool      `json:"topology_running"`
	At              time.Time `json:"at"`
	Nodes           []vizNode `json:"nodes"`
	Edges           []vizEdge `json:"edges"`
}

// wantEdge is an edge the inputs imply: its source plane (kind), its
// direction, and the label it must carry ("" = any).
type wantEdge struct{ from, kind, to, label string }

func (g graph) node(id string) (vizNode, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return vizNode{}, false
}

func (g graph) edge(from, kind, to string) (vizEdge, bool) {
	for _, e := range g.Edges {
		if e.From == from && e.Kind == kind && e.To == to {
			return e, true
		}
	}
	return vizEdge{}, false
}

func (g graph) hasAll(want []wantEdge) bool {
	for _, w := range want {
		e, ok := g.edge(w.from, w.kind, w.to)
		if !ok || (w.label != "" && e.Label != w.label) {
			return false
		}
	}
	return true
}

func (g graph) hasAny(want []wantEdge) bool {
	for _, w := range want {
		if _, ok := g.edge(w.from, w.kind, w.to); ok {
			return true
		}
	}
	return false
}

func (g graph) count(kind string) int {
	n := 0
	for _, e := range g.Edges {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func (g graph) describe() string {
	var nodes, edges []string
	for _, n := range g.Nodes {
		nodes = append(nodes, fmt.Sprintf("%s(%s %q)", n.ID, n.Kind, n.Label))
	}
	for _, e := range g.Edges {
		edges = append(edges, fmt.Sprintf("%s -%s-> %s %q", e.From, e.Kind, e.To, e.Label))
	}
	slices.Sort(nodes)
	slices.Sort(edges)
	return fmt.Sprintf("nodes [%s] edges [%s]", strings.Join(nodes, ", "), strings.Join(edges, ", "))
}

func pathEdges() []wantEdge {
	return []wantEdge{
		{"agent:control", "path", "hop:" + sharedAddr, ""},
		{"hop:" + sharedAddr, "path", "host:" + sharedAddr, ""},
	}
}

func (tn *topoTenant) deviceEdges() []wantEdge {
	return tn.deviceEdgesWith(tn.neighbor)
}

func (tn *topoTenant) deviceEdgesWith(n lldpNeighbor) []wantEdge {
	dev := "device:" + sharedAddr
	return []wantEdge{
		{dev, "device", "hop:" + sharedAddr, ""},
		{dev, "device", "hop:" + tn.device.ip, ""},
		{dev, "physical", n.nodeID(), "eth0 ↔ " + n.port},
	}
}

func (tn *topoTenant) routingEdges() []wantEdge {
	return []wantEdge{{"as:" + strconv.Itoa(int(tn.origin)), "routing", "prefix:" + tn.prefix, ""}}
}

// expectedNodes is the tenant's whole graph: its id -> kind and label.
func (tn *topoTenant) expectedNodes(n lldpNeighbor) map[string]vizNode {
	nodes := []vizNode{
		{"agent:control", "agent", "control"},
		{"hop:" + sharedAddr, "hop", sharedAddr},
		{"host:" + sharedAddr, "host", sharedAddr},
		{"device:" + sharedAddr, "device", tn.sysName},
		{"hop:" + tn.device.ip, "hop", tn.device.ip},
		{n.nodeID(), "device", n.name},
		{"as:" + strconv.Itoa(int(tn.origin)), "as", "AS" + strconv.Itoa(int(tn.origin))},
		{"prefix:" + tn.prefix, "prefix", tn.prefix},
	}
	out := map[string]vizNode{}
	for _, v := range nodes {
		out[v.ID] = v
	}
	return out
}

// checkGraph: the graph holds exactly the tenant's nodes (kind and label) and
// exactly the edges its inputs imply, each in the direction its plane
// states; the reverse of every edge is absent.
func (tn *topoTenant) checkGraph(t *testing.T, surface string, g graph, n lldpNeighbor) {
	t.Helper()
	if !g.TopologyRunning {
		t.Fatalf("%s as %s: topology_running=false", surface, tn.slug)
	}
	want := tn.expectedNodes(n)
	for _, got := range g.Nodes {
		w, ok := want[got.ID]
		if !ok {
			t.Errorf("%s as %s holds a node that none of its inputs imply: %s (%s %q)", surface, tn.slug, got.ID, got.Kind, got.Label)
			continue
		}
		if got != w {
			t.Errorf("%s as %s: node %s = %s %q, want %s %q", surface, tn.slug, got.ID, got.Kind, got.Label, w.Kind, w.Label)
		}
		delete(want, got.ID)
	}
	for id := range want {
		t.Errorf("%s as %s misses node %s", surface, tn.slug, id)
	}
	edges := slices.Concat(pathEdges(), tn.deviceEdgesWith(n), tn.routingEdges())
	if !g.hasAll(edges) {
		t.Errorf("%s as %s misses an edge of %+v: %s", surface, tn.slug, edges, g.describe())
	}
	if len(g.Edges) != len(edges) {
		t.Errorf("%s as %s holds %d edges, want exactly the %d its inputs imply: %s", surface, tn.slug, len(g.Edges), len(edges), g.describe())
	}
	for _, e := range edges {
		if _, reversed := g.edge(e.to, e.kind, e.from); reversed {
			t.Errorf("%s as %s holds %s -%s-> %s, the reverse of what its %s plane observed", surface, tn.slug, e.to, e.kind, e.from, e.kind)
		}
	}
}

func (tn *topoTenant) topologyAPI(t *testing.T, st *shipped.Stack, at string) graph {
	t.Helper()
	route := "/v1/topology"
	if at != "" {
		route += "?at=" + url.QueryEscape(at)
	}
	var g graph
	tn.do(t, st, http.MethodGet, route, nil, &g, http.StatusOK)
	return g
}

func (tn *topoTenant) topologyCLI(t *testing.T, st *shipped.Stack, at string) graph {
	t.Helper()
	args := []string{"topology", "show"}
	if at != "" {
		args = append(args, "--query", "at="+at)
	}
	var g graph
	tn.cli(t, st, &g, args...)
	return g
}

func (tn *topoTenant) awaitGraph(t *testing.T, st *shipped.Stack, what string, within time.Duration, done func(graph) bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		g := tn.topologyAPI(t, st, "")
		if done(g) {
			t.Logf("%s's graph holds %s", tn.slug, what)
			return
		}
		if time.Now().After(deadline) {
			agent := ""
			if tn.agentLog != "" {
				raw, _ := os.ReadFile(tn.agentLog)
				agent = tailLines(string(raw), 20)
			}
			t.Fatalf("GET /v1/topology as %s never held %s; it holds %s\ndevice agent log tail:\n%s", tn.slug, what, g.describe(), agent)
		}
		time.Sleep(time.Second)
	}
}

// --- the device plane ---

type registration struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	Plane    string `json:"plane"`
	Config   struct {
		Env  map[string]string `json:"env"`
		YAML map[string]any    `json:"yaml"`
	} `json:"config"`
}

func (tn *topoTenant) bindDevice(t *testing.T, surface string, reg registration) {
	t.Helper()
	env := reg.Config.Env
	if reg.TenantID != tn.id || reg.Plane != "device" || reg.AgentID == "" || env["PROBECTL_DEVICE_TENANT"] != tn.id ||
		env["PROBECTL_DEVICE_BUS_NAMESPACE"] == "" || reg.Config.YAML["collection_profile"] != tn.profile {
		t.Fatalf("%s as %s returned %+v, want a device collector bound to the tenant with its lane and the %s profile", surface, tn.slug, reg, tn.profile)
	}
	tn.collectorID, tn.hint = reg.AgentID, reg.Config.YAML
}

func (tn *topoTenant) registerDeviceAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	tn.do(t, st, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{"name": tn.sysName, "ttl_seconds": 600}, &tok, http.StatusCreated)
	var reg registration
	tn.do(t, st, http.MethodPost, "/v1/collectors/register", map[string]any{
		"token": tok.Token, "plane": "device", "hostname": tn.sysName, "collection_profile": tn.profile,
	}, &reg, http.StatusCreated)
	tn.bindDevice(t, "POST /v1/collectors/register", reg)
}

func (tn *topoTenant) registerDeviceCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	tn.cli(t, st, &tok, "agent", "enroll-token", "--body", fmt.Sprintf(`{"name":%q,"ttl_seconds":600}`, tn.sysName))
	var reg registration
	tn.cli(t, st, &reg, "collector", "register", "--body-file", st.SecretFile(t, map[string]any{
		"token": tok.Token, "plane": "device", "hostname": tn.sysName, "collection_profile": tn.profile,
	}))
	tn.bindDevice(t, "probectl collector register", reg)
}

// startDeviceAgent runs the tenant's shipped device agent on the YAML its
// registration returned plus the operator's device stanza; the community is
// a secret reference resolved from the environment.
func (tn *topoTenant) startDeviceAgent(t *testing.T, st *shipped.Stack) {
	t.Helper()
	cfg := map[string]any{"apiVersion": "probectl.io/device-agent/v1"}
	for k, v := range tn.hint {
		cfg[k] = v
	}
	overrides := map[string]any{"interval": pollInterval.String()}
	if tn.profile != "topology-rich" {
		overrides["neighbors"] = true
	}
	cfg["devices"] = []map[string]any{{
		"address": sharedAddr, "port": tn.device.port, "transport": "snmpv2c",
		"credential": tn.credential, "collection_overrides": overrides,
	}}
	raw, err := json.Marshal(cfg) // JSON is YAML
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(st.Dir, "device-agent-"+tn.slug+".yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cred := "PROBECTL_DEVICE_CRED_" + strings.ToUpper(strings.ReplaceAll(tn.credential, "-", "_")) + "_"
	secretVar := "PROBECTL_TEST_TOPOLOGY_SECRET_" + strings.ToUpper(strings.ReplaceAll(tn.slug, "-", "_"))
	env := []string{
		"PROBECTL_DEVICE_BUS_MODE=kafka",
		"PROBECTL_DEVICE_BUS_BROKERS=" + strings.Join(testsupport.KafkaBrokers(), ","),
		"PROBECTL_DEVICE_BUS_ALLOW_PLAINTEXT=true", // the dev stack's Kafka is plaintext
		"PROBECTL_DEVICE_METRICS_ADDR=" + shipped.FreeAddr(t),
		cred + "COMMUNITY=env:" + secretVar, secretVar + "=" + tn.community,
	}
	tn.agentLog = st.StartProcess(t, "device-agent-"+tn.slug, st.Binary(t, "probectl-device-agent"), []string{"-config", path}, env)
	shipped.Await(t, tn.slug+"'s device agent to start", 60*time.Second, func() bool {
		raw, _ := os.ReadFile(tn.agentLog)
		return strings.Contains(string(raw), `"device collector running"`)
	})
	t.Logf("%s's device agent %s polls %s (%s) at 127.0.0.1:%d every %s", tn.slug, tn.collectorID, tn.sysName, tn.profile, tn.device.port, pollInterval)
}

// --- the path plane ---

func (tn *topoTenant) createPathTest(t *testing.T, st *shipped.Stack) {
	t.Helper()
	tn.testName = "topology path " + tn.mark
	var test struct{ ID string }
	tn.do(t, st, http.MethodPost, "/v1/tests", map[string]any{
		"name": tn.testName, "type": "icmp", "target": sharedAddr, "interval_seconds": 60,
		"timeout_seconds": 3, "enabled": true, "params": map[string]string{"allow_private_targets": "true"},
	}, &test, http.StatusCreated)
	tn.testID = test.ID
}

type tracedPath struct {
	Target             string `json:"target"`
	TargetIP           string `json:"target_ip"`
	Vantage            string `json:"vantage"`
	DestinationReached bool   `json:"destination_reached"`
}

func (tn *topoTenant) checkTraced(t *testing.T, surface string, p tracedPath) {
	t.Helper()
	if p.Target != sharedAddr || p.TargetIP != sharedAddr || p.Vantage != "control_plane" || !p.DestinationReached {
		t.Fatalf("%s as %s = %+v, want a control-plane path that reached %s", surface, tn.slug, p, sharedAddr)
	}
}

func (tn *topoTenant) discoverAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var p tracedPath
	tn.do(t, st, http.MethodPost, "/v1/tests/"+tn.testID+"/path", nil, &p, http.StatusOK)
	tn.checkTraced(t, "POST /v1/tests/{id}/path", p)
}

func (tn *topoTenant) discoverCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var p tracedPath
	tn.cli(t, st, &p, "test", "path", tn.testID, "--body", "{}")
	tn.checkTraced(t, "probectl test path --body", p)
}

// --- the BGP plane ---

func (tn *topoTenant) bindBGP(t *testing.T, surface string, reg registration) {
	t.Helper()
	env := reg.Config.Env
	if reg.TenantID != tn.id || reg.Plane != "bgp" || reg.AgentID == "" || env["PROBECTL_BMP_TENANT_ID"] != tn.id ||
		env["PROBECTL_BMP_BUS_NAMESPACE"] == "" {
		t.Fatalf("%s as %s returned %+v, want a bgp source bound to the tenant with its lane", surface, tn.slug, reg)
	}
	tn.bgpSource, tn.bgpLane = reg.AgentID, env["PROBECTL_BMP_BUS_NAMESPACE"]
}

func (tn *topoTenant) setupBGPAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	tn.do(t, st, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{"name": labCollector, "ttl_seconds": 600}, &tok, http.StatusCreated)
	var reg registration
	tn.do(t, st, http.MethodPost, "/v1/collectors/register",
		map[string]any{"token": tok.Token, "plane": "bgp", "hostname": labCollector}, &reg, http.StatusCreated)
	tn.bindBGP(t, "POST /v1/collectors/register", reg)
}

func (tn *topoTenant) setupBGPCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	tn.cli(t, st, &tok, "agent", "enroll-token", "--body", fmt.Sprintf(`{"name":%q,"ttl_seconds":600}`, labCollector))
	var reg registration
	tn.cli(t, st, &reg, "bgp", "setup", "--body-file", st.SecretFile(t,
		map[string]any{"token": tok.Token, "plane": "bgp", "hostname": labCollector}))
	tn.bindBGP(t, "probectl bgp setup", reg)
}

// runAnalyzer runs the tenant's shipped analyzer sidecar once over the lab
// collector's MRT (baseline route, then the changed path) with the tenant's
// own watch config, publishing on the tenant's lane.
func (tn *topoTenant) runAnalyzer(t *testing.T, st *shipped.Stack, python string) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "analyzer.json")
	writeJSONFile(t, cfg, map[string]any{"tenant_id": tn.id, "collector": labCollector, "monitored_prefixes": []map[string]any{tn.watch}})
	mrt := writeMRT(t, tn.prefix, tn.baseline, tn.changed)
	cmd := exec.Command(st.Control, "bgp-analyzer")
	cmd.Dir = st.Dir
	cmd.Env = append(os.Environ(),
		"PROBECTL_BGP_ANALYZER_CONFIG="+cfg,
		"PROBECTL_BGP_ANALYZER_SOURCE=mrt",
		"PROBECTL_BGP_ANALYZER_SOURCE_FILE="+mrt,
		"PROBECTL_BGP_ANALYZER_BUS_NAMESPACE="+tn.bgpLane,
		"PROBECTL_BGP_ANALYZER_PYTHON="+python,
		"PYTHONPATH="+filepath.Join(st.Root, "analyzer"),
		"PROBECTL_BUS_MODE=kafka",
		"PROBECTL_BUS_BROKERS="+strings.Join(testsupport.KafkaBrokers(), ","),
		"PROBECTL_BUS_ALLOW_PLAINTEXT=true", // the dev stack's Kafka is plaintext
	)
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(st.Dir, "bgp-analyzer-"+tn.slug+".log"), out, 0o600)
	if err != nil || !strings.Contains(string(out), `"bgp analyzer completed"`) {
		t.Fatalf("probectl-control bgp-analyzer (mrt) for %s: %v\n%s", tn.slug, err, out)
	}
	t.Logf("%s's analyzer sidecar read the lab collector's MRT: %s, path %v -> %v", tn.slug, tn.prefix, tn.baseline, tn.changed)
}

// writeMRT encodes the lab collector's MRT (RFC 6396): a TABLE_DUMP_V2 RIB
// holding the baseline route, then one BGP4MP_MESSAGE_AS4 UPDATE announcing
// the changed path, both stamped now.
func writeMRT(t *testing.T, prefix string, baseline, changed []uint32) string {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	ts := uint32(time.Now().Unix()) //nolint:gosec // seconds since 1970 fit uint32 until 2106
	var raw []byte
	raw = append(raw, mrtPeerIndexTable(ts)...)
	raw = append(raw, mrtRIBIPv4(ts, p, baseline)...)
	raw = append(raw, mrtUpdateAS4(ts+1, p, changed)...)
	path := filepath.Join(t.TempDir(), "updates.mrt")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mrtRecord(ts uint32, typ, subtype uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, ts)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, subtype)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body))) //nolint:gosec // a few dozen bytes
	return append(b, body...)
}

func mrtASPath(asns []uint32) []byte {
	seg := []byte{2, byte(len(asns))} // AS_SEQUENCE
	for _, a := range asns {
		seg = binary.BigEndian.AppendUint32(seg, a)
	}
	return append([]byte{0x40, 2, byte(len(seg))}, seg...) // well-known transitive AS_PATH
}

func mrtNLRI(p netip.Prefix) []byte {
	a := p.Addr().As4()
	return append([]byte{byte(p.Bits())}, a[:(p.Bits()+7)/8]...)
}

var (
	mrtPeerIP  = netip.MustParseAddr("192.0.2.1").As4()
	mrtLocalIP = netip.MustParseAddr("192.0.2.2").As4()
)

func mrtPeerIndexTable(ts uint32) []byte {
	b := binary.BigEndian.AppendUint32(nil, 1)         // collector BGP id
	b = binary.BigEndian.AppendUint16(b, 0)            // empty view name
	b = binary.BigEndian.AppendUint16(b, 1)            // one peer
	b = append(b, 0x02)                                // IPv4 address, 4-byte ASN
	b = binary.BigEndian.AppendUint32(b, 0)            // peer BGP id
	b = append(b, mrtPeerIP[:]...)                     // peer address
	b = binary.BigEndian.AppendUint32(b, collectorASN) // peer AS
	return mrtRecord(ts, 13, 1, b)                     // TABLE_DUMP_V2 / PEER_INDEX_TABLE
}

func mrtRIBIPv4(ts uint32, p netip.Prefix, asns []uint32) []byte {
	attrs := mrtASPath(asns)
	b := binary.BigEndian.AppendUint32(nil, 0) // sequence
	b = append(b, mrtNLRI(p)...)
	b = binary.BigEndian.AppendUint16(b, 1)                  // one entry
	b = binary.BigEndian.AppendUint16(b, 0)                  // peer index
	b = binary.BigEndian.AppendUint32(b, ts)                 // originated
	b = binary.BigEndian.AppendUint16(b, uint16(len(attrs))) //nolint:gosec // one short attribute
	b = append(b, attrs...)
	return mrtRecord(ts, 13, 2, b) // TABLE_DUMP_V2 / RIB_IPV4_UNICAST
}

func mrtUpdateAS4(ts uint32, p netip.Prefix, asns []uint32) []byte {
	attrs := mrtASPath(asns)
	update := binary.BigEndian.AppendUint16(nil, 0)                    // no withdrawals
	update = binary.BigEndian.AppendUint16(update, uint16(len(attrs))) //nolint:gosec // one short attribute
	update = append(update, attrs...)
	update = append(update, mrtNLRI(p)...)
	msg := bytes.Repeat([]byte{0xff}, 16)
	msg = binary.BigEndian.AppendUint16(msg, uint16(19+len(update))) //nolint:gosec // one short UPDATE
	msg = append(msg, 2)                                             // UPDATE
	msg = append(msg, update...)
	b := binary.BigEndian.AppendUint32(nil, collectorASN) // peer AS
	b = binary.BigEndian.AppendUint32(b, 0)               // local AS
	b = binary.BigEndian.AppendUint16(b, 0)               // interface index
	b = binary.BigEndian.AppendUint16(b, 1)               // AFI IPv4
	b = append(b, mrtPeerIP[:]...)
	b = append(b, mrtLocalIP[:]...)
	b = append(b, msg...)
	return mrtRecord(ts, 16, 4, b) // BGP4MP / BGP4MP_MESSAGE_AS4
}

// --- what-if ---

type pathImpact struct {
	From  string   `json:"from"`
	To    string   `json:"to"`
	Route []string `json:"route"`
}

type testImpact struct {
	AgentID string `json:"agent_id"`
	Target  string `json:"target"`
	Status  string `json:"status"`
}

type impact struct {
	Target           string       `json:"target"`
	TargetKind       string       `json:"target_kind"`
	BrokenPaths      []pathImpact `json:"broken_paths"`
	ReroutedPaths    []pathImpact `json:"rerouted_paths"`
	ImpactedTests    []testImpact `json:"impacted_tests"`
	ImpactedPrefixes []string     `json:"impacted_prefixes"`
	ImpactedServices []string     `json:"impacted_services"`
	Disconnected     []string     `json:"disconnected"`
	Partial          bool         `json:"partial"`
	Coverage         struct {
		PathEdges     int `json:"path_edges"`
		RoutingEdges  int `json:"routing_edges"`
		DeviceEdges   int `json:"device_edges"`
		PhysicalEdges int `json:"physical_edges"`
	} `json:"coverage"`
}

func (tn *topoTenant) whatIfAPI(t *testing.T, st *shipped.Stack, target string) impact {
	t.Helper()
	var out impact
	tn.do(t, st, http.MethodPost, "/v1/topology/whatif", map[string]any{"target": target}, &out, http.StatusOK)
	return out
}

func (tn *topoTenant) whatIfCLI(t *testing.T, st *shipped.Stack, target string) impact {
	t.Helper()
	var out impact
	tn.cli(t, st, &out, "topology", "whatif", "--body", fmt.Sprintf(`{"target":%q}`, target))
	return out
}

// downstream is what failing hop:127.0.0.1 cuts off from the control plane's
// vantage: the traced host, and the tenant's device with everything only it
// connects (its eth0 hop and its LLDP neighbor).
func (tn *topoTenant) downstream() []string {
	out := []string{"host:" + sharedAddr, "device:" + sharedAddr, "hop:" + tn.device.ip, tn.neighbor.nodeID()}
	slices.Sort(out)
	return out
}

func (tn *topoTenant) checkWhatIf(t *testing.T, st *shipped.Stack, other *topoTenant) {
	t.Helper()
	hop := "hop:" + sharedAddr
	for surface, imp := range map[string]impact{
		"POST /v1/topology/whatif (hop)": tn.whatIfAPI(t, st, hop),
		"probectl topology whatif (hop)": tn.whatIfCLI(t, st, hop),
	} {
		route := []string{"agent:control", hop, "host:" + sharedAddr}
		if imp.Target != hop || imp.TargetKind != "hop" || imp.Partial || len(imp.BrokenPaths) != 1 || len(imp.ReroutedPaths) != 0 ||
			imp.BrokenPaths[0].From != "agent:control" || imp.BrokenPaths[0].To != "host:"+sharedAddr || !slices.Equal(imp.BrokenPaths[0].Route, route) {
			t.Errorf("%s as %s: target %q (%s) broken %+v rerouted %+v partial %v, want exactly the control plane's path %v broken",
				surface, tn.slug, imp.Target, imp.TargetKind, imp.BrokenPaths, imp.ReroutedPaths, imp.Partial, route)
		}
		if len(imp.ImpactedTests) != 1 || imp.ImpactedTests[0].AgentID != "agent:control" || imp.ImpactedTests[0].Target != "host:"+sharedAddr ||
			imp.ImpactedTests[0].Status != "broken" {
			t.Errorf("%s as %s: impacted tests %+v, want the control plane's test of %s, broken", surface, tn.slug, imp.ImpactedTests, sharedAddr)
		}
		got := slices.Sorted(slices.Values(imp.Disconnected))
		if !slices.Equal(got, tn.downstream()) {
			t.Errorf("%s as %s: disconnected %v, want exactly its own downstream %v", surface, tn.slug, got, tn.downstream())
		}
		if len(imp.ImpactedPrefixes) != 0 || len(imp.ImpactedServices) != 0 {
			t.Errorf("%s as %s: impacted prefixes %v services %v, want none for a hop", surface, tn.slug, imp.ImpactedPrefixes, imp.ImpactedServices)
		}
		if imp.Coverage.PathEdges != 2 || imp.Coverage.DeviceEdges != 2 || imp.Coverage.PhysicalEdges != 1 || imp.Coverage.RoutingEdges != 1 {
			t.Errorf("%s as %s: coverage %+v, want the tenant's own 2 path, 2 device, 1 physical and 1 routing edges", surface, tn.slug, imp.Coverage)
		}
	}
	as := "as:" + strconv.Itoa(int(tn.origin))
	for surface, imp := range map[string]impact{
		"POST /v1/topology/whatif (origin AS)": tn.whatIfAPI(t, st, as),
		"probectl topology whatif (origin AS)": tn.whatIfCLI(t, st, as),
	} {
		if imp.TargetKind != "as" || !slices.Equal(imp.ImpactedPrefixes, []string{"prefix:" + tn.prefix}) || len(imp.BrokenPaths) != 0 {
			t.Errorf("%s as %s: kind %q prefixes %v broken %v, want exactly prefix:%s and no path", surface, tn.slug, imp.TargetKind, imp.ImpactedPrefixes, imp.BrokenPaths, tn.prefix)
		}
	}
	// The other tenant's elements do not exist in this tenant's graph.
	for _, foreign := range []string{other.neighbor.nodeID(), "as:" + strconv.Itoa(int(other.origin)), "hop:" + other.device.ip} {
		if code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/topology/whatif", map[string]any{"target": foreign}); code != http.StatusNotFound {
			t.Errorf("POST /v1/topology/whatif %s (%s's) as %s = %d, want 404: %.300s", foreign, other.slug, tn.slug, code, raw)
		}
		if out, _, code := st.CLI(tn.env(), "topology", "whatif", "--body", fmt.Sprintf(`{"target":%q}`, foreign)); code == 0 {
			t.Errorf("probectl topology whatif %s (%s's) as %s succeeded: %.300s", foreign, other.slug, tn.slug, out)
		}
	}
	t.Logf("%s: failing %s breaks agent:control -> host:%s and disconnects %v; failing %s impacts prefix:%s; %s's elements are unknown",
		tn.slug, hop, sharedAddr, tn.downstream(), as, tn.prefix, other.slug)
}

// --- the incident walk ---

type incidentRecord struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
	Signals  []struct {
		Plane      string            `json:"plane"`
		Kind       string            `json:"kind"`
		Prefix     string            `json:"prefix"`
		Attributes map[string]string `json:"attributes"`
	} `json:"signals"`
}

func (tn *topoTenant) incidents(t *testing.T, st *shipped.Stack) []incidentRecord {
	t.Helper()
	var list struct {
		Items []incidentRecord `json:"items"`
	}
	tn.do(t, st, http.MethodGet, "/v1/incidents", nil, &list, http.StatusOK)
	out := make([]incidentRecord, 0, len(list.Items))
	for _, inc := range list.Items {
		var full incidentRecord
		tn.do(t, st, http.MethodGet, "/v1/incidents/"+url.PathEscape(inc.ID), nil, &full, http.StatusOK)
		out = append(out, full)
	}
	return out
}

func kindsOf(inc incidentRecord) []string {
	out := make([]string, 0, len(inc.Signals))
	for _, s := range inc.Signals {
		out = append(out, s.Kind)
	}
	slices.Sort(out)
	return out
}

func (tn *topoTenant) awaitIncident(t *testing.T, st *shipped.Stack) {
	t.Helper()
	want := slices.Sorted(slices.Values(tn.incident))
	deadline := time.Now().Add(120 * time.Second)
	for {
		incs := tn.incidents(t, st)
		if len(incs) == 1 && slices.Equal(kindsOf(incs[0]), want) {
			tn.incidentID = incs[0].ID
			return
		}
		if time.Now().After(deadline) {
			var got [][]string
			for _, inc := range incs {
				got = append(got, kindsOf(inc))
			}
			t.Fatalf("%s never had exactly one incident of %v; it has %v", tn.slug, want, got)
		}
		time.Sleep(time.Second)
	}
}

// checkIncidentInGraph: every signal of the tenant's incident names its
// prefix and new origin AS, and both are nodes of the tenant's graph joined
// by the routing edge the event implies.
func (tn *topoTenant) checkIncidentInGraph(t *testing.T, st *shipped.Stack) {
	t.Helper()
	incs := tn.incidents(t, st)
	g := tn.topologyAPI(t, st, "")
	for _, inc := range incs {
		if inc.TenantID != tn.id || inc.Status != "open" {
			t.Errorf("%s's incident %s = tenant %q status %q", tn.slug, inc.ID, inc.TenantID, inc.Status)
		}
		for _, s := range inc.Signals {
			origin := s.Attributes["new_origin_asn"]
			as, pfx := "as:"+origin, "prefix:"+s.Prefix
			_, asOK := g.node(as)
			_, pfxOK := g.node(pfx)
			_, edgeOK := g.edge(as, "routing", pfx)
			if s.Plane != "bgp" || s.Prefix != tn.prefix || origin != strconv.Itoa(int(tn.origin)) || !asOK || !pfxOK || !edgeOK {
				t.Errorf("%s's incident signal %s (prefix %q, origin %q) does not walk to its graph's %s -routing-> %s (%v %v %v): %s",
					tn.slug, s.Kind, s.Prefix, origin, as, pfx, asOK, pfxOK, edgeOK, g.describe())
			}
		}
	}
	t.Logf("%s: incident %s's signals %v name %s and AS%d, joined in its graph", tn.slug, tn.incidentID, kindsOf(incs[0]), tn.prefix, tn.origin)
}

type rcaEvidence struct {
	ID     string         `json:"id"`
	Domain string         `json:"domain"`
	Plane  string         `json:"plane"`
	Title  string         `json:"title"`
	Fields map[string]any `json:"fields"`
}

type rcaAnswer struct {
	Tenant             string `json:"tenant"`
	RootCause          string `json:"root_cause"`
	RootCauseGrounded  bool   `json:"root_cause_grounded"`
	RootCauseCitations []struct {
		EvidenceID string `json:"evidence_id"`
	} `json:"root_cause_citations"`
	Findings []struct {
		Citations []struct {
			EvidenceID string `json:"evidence_id"`
		} `json:"citations"`
	} `json:"findings"`
	InvestigationPlan []struct {
		Domain string `json:"domain"`
		Status string `json:"status"`
	} `json:"investigation_plan"`
	Evidence             []rcaEvidence `json:"evidence"`
	Model                string        `json:"model"`
	InsufficientEvidence bool          `json:"insufficient_evidence"`
}

func (tn *topoTenant) askAPI(t *testing.T, st *shipped.Stack, question string) rcaAnswer {
	t.Helper()
	var ans rcaAnswer
	tn.do(t, st, http.MethodPost, "/v1/ai/ask", map[string]any{"question": question}, &ans, http.StatusOK)
	return ans
}

func (tn *topoTenant) askCLI(t *testing.T, st *shipped.Stack, question string) rcaAnswer {
	t.Helper()
	var ans rcaAnswer
	body, err := json.Marshal(map[string]any{"question": question})
	if err != nil {
		t.Fatal(err)
	}
	tn.cli(t, st, &ans, "ai", "ask", "--body", string(body))
	return ans
}

func evField(e rcaEvidence, key string) string {
	v, _ := e.Fields[key].(string)
	return v
}

// topologyWalk is the topology evidence of an answer: the nodes it cites
// (id -> label) and the edges it walked (node, neighbor, kind).
func topologyWalk(ans rcaAnswer) (nodes map[string]string, edges map[wantEdge]bool) {
	nodes, edges = map[string]string{}, map[wantEdge]bool{}
	for _, e := range ans.Evidence {
		if e.Domain != "topology" {
			continue
		}
		node, neighbor := evField(e, "node"), evField(e, "neighbor")
		if neighbor == "" {
			nodes[node] = evField(e, "label")
			continue
		}
		edges[wantEdge{from: node, kind: evField(e, "kind"), to: neighbor}] = true
	}
	return nodes, edges
}

// checkRCA asks why the shared address fails (API and CLI) and the tenant's
// own routing question (CLI): every answer is the builtin adapter's for this
// tenant, its citations resolve to its evidence, and its topology evidence
// walks the tenant's own graph — every node and neighbor it names is in the
// tenant's graph, and the walk reaches what the tenant's inputs connect.
func (tn *topoTenant) checkRCA(t *testing.T, st *shipped.Stack) {
	t.Helper()
	g := tn.topologyAPI(t, st, "")
	address := "Why is the service at " + sharedAddr + " failing?"
	dev := "device:" + sharedAddr
	for surface, ans := range map[string]rcaAnswer{
		"POST /v1/ai/ask (address)": tn.askAPI(t, st, address),
		"probectl ai ask (address)": tn.askCLI(t, st, address),
		"probectl ai ask (routing)": tn.askCLI(t, st, tn.question2),
	} {
		if ans.Tenant != tn.id || ans.Model != "builtin" {
			t.Errorf("%s as %s: tenant %q model %q, want the tenant's builtin answer", surface, tn.slug, ans.Tenant, ans.Model)
		}
		held := map[string]bool{}
		for _, e := range ans.Evidence {
			held[e.ID] = true
		}
		cites := ans.RootCauseCitations
		for _, f := range ans.Findings {
			cites = append(cites, f.Citations...)
		}
		for _, c := range cites {
			if !held[c.EvidenceID] {
				t.Errorf("%s as %s cites evidence %q it does not hold", surface, tn.slug, c.EvidenceID)
			}
		}
		for _, step := range ans.InvestigationPlan {
			if step.Domain == "topology" && step.Status != "queried" {
				t.Errorf("%s as %s: the topology step is %s", surface, tn.slug, step.Status)
			}
		}
		nodes, edges := topologyWalk(ans)
		for id, label := range nodes {
			if n, ok := g.node(id); !ok || n.Label != label {
				t.Errorf("%s as %s cites topology node %s %q, not a node of its graph", surface, tn.slug, id, label)
			}
		}
		for e := range edges {
			_, fwd := g.edge(e.from, e.kind, e.to)
			_, rev := g.edge(e.to, e.kind, e.from)
			if !fwd && !rev {
				t.Errorf("%s as %s walked %s -%s- %s, not an edge of its graph", surface, tn.slug, e.from, e.kind, e.to)
			}
		}
		var want []wantEdge
		var wantNodes map[string]string
		if strings.Contains(surface, "(address)") {
			wantNodes = map[string]string{"host:" + sharedAddr: sharedAddr, "hop:" + sharedAddr: sharedAddr, dev: tn.sysName}
			want = []wantEdge{
				{from: "hop:" + sharedAddr, kind: "path", to: "agent:control"},
				{from: dev, kind: "device", to: "hop:" + tn.device.ip},
				{from: dev, kind: "physical", to: tn.neighbor.nodeID()},
			}
			if netip.MustParsePrefix(tn.prefix).Contains(netip.MustParseAddr(sharedAddr)) {
				// The host sits in the tenant's hijacked block: the walk
				// reaches the origin that carries it, the cause.
				wantNodes["prefix:"+tn.prefix] = tn.prefix
				want = append(want, wantEdge{from: "prefix:" + tn.prefix, kind: "routing", to: "as:" + strconv.Itoa(int(tn.origin))})
				if !ans.RootCauseGrounded || !strings.Contains(ans.RootCause, tn.prefix) {
					t.Errorf("%s as %s: root cause %q (grounded %v), want the grounded fault on %s", surface, tn.slug, ans.RootCause, ans.RootCauseGrounded, tn.prefix)
				}
			} else if !ans.InsufficientEvidence || ans.RootCauseGrounded || !strings.HasPrefix(ans.RootCause, "Insufficient evidence: only topology context") {
				// No fault of this tenant's touches the address: its own
				// graph is context, not a cause, and the other tenant's
				// fault on the same address must not answer.
				t.Errorf("%s as %s: root cause %q (grounded %v, insufficient %v), want insufficient evidence over its own topology context",
					surface, tn.slug, ans.RootCause, ans.RootCauseGrounded, ans.InsufficientEvidence)
			}
		} else {
			wantNodes = map[string]string{"prefix:" + tn.prefix: tn.prefix}
			want = []wantEdge{{from: "prefix:" + tn.prefix, kind: "routing", to: "as:" + strconv.Itoa(int(tn.origin))}}
			if !ans.RootCauseGrounded || !strings.Contains(ans.RootCause, tn.prefix) {
				t.Errorf("%s as %s: root cause %q (grounded %v), want the grounded fault on %s", surface, tn.slug, ans.RootCause, ans.RootCauseGrounded, tn.prefix)
			}
		}
		for id, label := range wantNodes {
			if nodes[id] != label {
				t.Errorf("%s as %s: topology evidence has node %s = %q, want %q (walk %v)", surface, tn.slug, id, nodes[id], label, nodes)
			}
		}
		for _, w := range want {
			if !edges[w] {
				t.Errorf("%s as %s: the topology walk misses %s -%s- %s (walked %v)", surface, tn.slug, w.from, w.kind, w.to, edges)
			}
		}
		t.Logf("%s as %s: %q; topology walk %d nodes, %d edges", surface, tn.slug, ans.RootCause, len(nodes), len(edges))
	}
}

// --- the rendered page ---

// renderTopology loads the tenant's Topology page, selects hop 127.0.0.1 in
// the graph and simulates its failure.
func (tn *topoTenant) renderTopology(t *testing.T, st *shipped.Stack, other *topoTenant) {
	t.Helper()
	expect := []string{"Topology", "Live topology", "Dependency graph", tn.sysName, tn.neighbor.name, tn.neighbor.nodeID(),
		"hop:" + tn.device.ip, "prefix:" + tn.prefix, "AS" + strconv.Itoa(int(tn.origin)), "agent:control", "host:" + sharedAddr}
	page := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/topology",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: expect,
		Steps: []testsupport.RenderStep{
			{Click: "hop " + sharedAddr, Expect: []string{"Inspector", "hop:" + sharedAddr, "Simulate failure (dry-run)"}},
			{Click: "Simulate failure (dry-run)", Expect: []string{"Predicted impact · observe-only dry-run",
				"agent:control → host:" + sharedAddr, "agent:control → hop:" + sharedAddr + " → host:" + sharedAddr,
				tn.neighbor.nodeID(), "hop:" + tn.device.ip}},
		},
		Absent: tn.foreignIdentifiers(other),
	}
	res := testsupport.RenderUI(t, page)
	tn.keep([]byte(res.Text))
	t.Logf("the rendered Topology page shows %s its graph and the what-if of hop %s", tn.slug, sharedAddr)
}

// renderLive: after the neighbor change the page shows the new adjacency and
// neither the old neighbor nor anything of the other tenant's.
func (tn *topoTenant) renderLive(t *testing.T, st *shipped.Stack, other *topoTenant) {
	t.Helper()
	page := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/topology",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Live topology", tn.sysName, tn.next.name, tn.next.nodeID()},
		Absent: append([]string{tn.neighbor.name, tn.neighbor.nodeID()}, tn.foreignIdentifiers(other)...),
	}
	res := testsupport.RenderUI(t, page)
	tn.keep([]byte(res.Text))
	t.Logf("the rendered Topology page shows %s its new neighbor %s and not %s", tn.slug, tn.next.name, tn.neighbor.name)
}

// checkNothingOf byte-searches everything this tenant was shown for the
// other tenant's identifiers.
func (tn *topoTenant) checkNothingOf(t *testing.T, other *topoTenant) {
	t.Helper()
	tn.mu.Lock()
	defer tn.mu.Unlock()
	if len(tn.seen) == 0 {
		t.Fatalf("nothing was shown to %s to search", tn.slug)
	}
	for i, raw := range tn.seen {
		for _, id := range tn.foreignIdentifiers(other) {
			if bytes.Contains(raw, []byte(id)) {
				t.Errorf("response/page %d shown to %s holds %q of %s's: %.400s", i, tn.slug, id, other.slug, raw)
			}
		}
	}
	t.Logf("%d responses, CLI outputs and pages shown to %s hold nothing of %s's", len(tn.seen), tn.slug, other.slug)
}

// --- the SNMP lab ---

// snmpLab is one net-snmp snmpd container per tenant.
type snmpLab struct{ name, image string }

// snmpDevice is one lab device: snmpd under a shell that restarts it when
// its configuration changes (the device keeps its container, address and
// published port), and its loopback port.
type snmpDevice struct {
	lab       *snmpLab
	container string
	port      int
	ip        string // the container's eth0 address on the docker bridge
}

func startSNMPLab(t *testing.T) *snmpLab {
	t.Helper()
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		testsupport.SkipOrFatal(t, "the topology receipt runs real SNMP agents in docker: %v %s", err, out)
	}
	lab := &snmpLab{name: os.Getenv("PROBECTL_TEST_DEVICE_LAB_NAME"), image: "probectl-it-snmpd:alpine-3.22.6"}
	if lab.name == "" {
		lab.name = "probectl-it-topology-" + strconv.FormatInt(time.Now().UnixNano()%1e8, 36)
	}
	dockerfile := "FROM " + snmpdBase + "\nRUN apk add --no-cache net-snmp net-snmp-tools\n"
	var out []byte
	var err error
	for attempt := 0; attempt < 3; attempt++ { // registry pulls fail transiently
		cmd := exec.Command("docker", "build", "-q", "-t", lab.image, "-")
		cmd.Stdin = strings.NewReader(dockerfile)
		if out, err = cmd.CombinedOutput(); err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		t.Fatalf("build the lab's snmpd image from %s: %v\n%s", snmpdBase, err, out)
	}
	return lab
}

func (lab *snmpLab) docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		// The argv can carry a lab community; name the verb only.
		t.Fatalf("docker %s: %v\n%s", args[0], err, out)
	}
	return string(out)
}

// startDevice starts the tenant's SNMP agent with its identity, its
// community and its LLDP neighbor.
func (lab *snmpLab) startDevice(t *testing.T, tn *topoTenant) *snmpDevice {
	t.Helper()
	short := strings.SplitN(tn.sysName, "-", 2)[0]
	d := &snmpDevice{lab: lab, container: lab.name + "-snmpd-" + short}
	_ = exec.Command("docker", "rm", "-f", d.container).Run()
	lab.docker(t, "create", "--name", d.container, "-p", "127.0.0.1::161/udp", lab.image,
		"sh", "-c", "while :; do snmpd -f -Lo -C -c /etc/snmp/snmpd.conf udp:161; sleep 0.2; done")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "15", d.container).CombinedOutput()
			t.Logf("snmpd %s log tail:\n%s", d.container, out)
		}
		_ = exec.Command("docker", "rm", "-f", d.container).Run()
	})
	d.configure(t, tn, tn.neighbor)
	lab.docker(t, "start", d.container)
	d.awaitNeighbor(t, tn, tn.neighbor)
	hostPort := strings.TrimSpace(lab.docker(t, "port", d.container, "161/udp"))
	for _, line := range strings.Split(hostPort, "\n") {
		if p, ok := strings.CutPrefix(line, "127.0.0.1:"); ok {
			d.port, _ = strconv.Atoi(p)
		}
	}
	if d.port == 0 {
		t.Fatalf("docker port %s 161/udp = %q, want a 127.0.0.1 binding", d.container, hostPort)
	}
	d.ip = strings.TrimSpace(lab.docker(t, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", d.container))
	if addr, err := netip.ParseAddr(d.ip); err != nil || !addr.Is4() {
		t.Fatalf("device %s's eth0 address %q is not IPv4", d.container, d.ip)
	}
	t.Logf("device %s (%s) answers on 127.0.0.1:%d; eth0 is %s; LLDP neighbor %s on %s", tn.sysName, d.container, d.port, d.ip, tn.neighbor.name, tn.neighbor.port)
	return d
}

// configure writes the device's snmpd and client configuration: its sysName,
// its community and one LLDP-MIB remote system learned on eth0 (local port 2,
// lldpRemTimeMark 0, lldpRemIndex 1), served by snmpd's override directives.
func (d *snmpDevice) configure(t *testing.T, tn *topoTenant, n lldpNeighbor) {
	t.Helper()
	var agent strings.Builder
	fmt.Fprintf(&agent, "rocommunity %s\nsysName %s\nsysLocation %s lab\n", tn.community, tn.sysName, tn.name)
	for _, row := range [][2]string{
		{".1.0.8802.1.1.2.1.3.7.1.2.2", "integer 5"}, // lldpLocPortIdSubtype: interfaceName
		{".1.0.8802.1.1.2.1.3.7.1.3.2", `octet_str "eth0"`},
		{".1.0.8802.1.1.2.1.3.7.1.4.2", `octet_str "uplink"`},
		{".1.0.8802.1.1.2.1.4.1.1.4.0.2.1", "integer 4"}, // lldpRemChassisIdSubtype: macAddress
		{".1.0.8802.1.1.2.1.4.1.1.5.0.2.1", fmt.Sprintf("octet_str %q", n.chassis)},
		{".1.0.8802.1.1.2.1.4.1.1.6.0.2.1", "integer 5"}, // lldpRemPortIdSubtype: interfaceName
		{".1.0.8802.1.1.2.1.4.1.1.7.0.2.1", fmt.Sprintf("octet_str %q", n.port)},
		{".1.0.8802.1.1.2.1.4.1.1.8.0.2.1", `octet_str "uplink"`},
		{".1.0.8802.1.1.2.1.4.1.1.9.0.2.1", fmt.Sprintf("octet_str %q", n.name)},
		{".1.0.8802.1.1.2.1.4.1.1.10.0.2.1", fmt.Sprintf("octet_str %q", tn.name+" lab neighbor")},
	} {
		fmt.Fprintf(&agent, "override %s %s\n", row[0], row[1])
	}
	client := fmt.Sprintf("defVersion 2c\ndefCommunity %s\n", tn.community)
	dir := t.TempDir()
	for name, body := range map[string]string{"snmpd.conf": agent.String(), "snmp.conf": client} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		d.lab.docker(t, "cp", p, d.container+":/etc/snmp/"+name)
	}
}

// awaitNeighbor waits until the device's own snmpd serves n as its LLDP
// neighbor.
func (d *snmpDevice) awaitNeighbor(t *testing.T, tn *topoTenant, n lldpNeighbor) {
	t.Helper()
	shipped.Await(t, d.container+" to report LLDP neighbor "+n.name, 30*time.Second, func() bool {
		out, err := exec.Command("docker", "exec", d.container, "snmpget", "-t", "1", "-r", "0", "-Ovq", "127.0.0.1",
			"SNMPv2-MIB::sysName.0", ".1.0.8802.1.1.2.1.4.1.1.9.0.2.1").Output()
		var got []string
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			got = append(got, strings.Trim(strings.TrimSpace(line), `"`))
		}
		return err == nil && slices.Equal(got, []string{tn.sysName, n.name})
	})
}

// setNeighbor rewires the device: its LLDP-MIB now reports n on eth0, as
// when the cable on the uplink is moved to another switch. snmpd restarts
// under its supervising shell; the device keeps its address and port.
func (d *snmpDevice) setNeighbor(t *testing.T, tn *topoTenant, n lldpNeighbor) {
	t.Helper()
	d.configure(t, tn, n)
	d.lab.docker(t, "exec", d.container, "pkill", "-x", "snmpd")
	d.awaitNeighbor(t, tn, n)
	t.Logf("%s now reports LLDP neighbor %s (%s) on eth0 instead of %s", tn.sysName, n.name, n.port, tn.neighbor.name)
}

// --- helpers ---

// analyzerPython is the interpreter the analyzer sidecar runs: CI's python3
// with the hash-locked runtime (analyzer/requirements.lock) installed, or
// PROBECTL_TEST_BGP_ANALYZER_PYTHON.
func analyzerPython(t *testing.T) string {
	t.Helper()
	python := os.Getenv("PROBECTL_TEST_BGP_ANALYZER_PYTHON")
	if python == "" {
		python = "python3"
	}
	if out, err := exec.Command(python, "-c", "import structlog, websockets").CombinedOutput(); err != nil {
		testsupport.SkipOrFatal(t, "the BGP analyzer needs %s with analyzer/requirements.lock installed (CI: pip install --require-hashes -r analyzer/requirements.lock): %v %s", python, err, out)
	}
	return python
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
