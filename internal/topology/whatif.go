// SPDX-License-Identifier: LicenseRef-probectl-TBD

package topology

// What-if / impact simulation (S43, F40-full): "if node/link X fails, what
// paths, services, and prefixes break?" The simulator traverses the VERSIONED
// graph at the requested time, removes the failed element, and recomputes
// reachability — so an operator can rehearse a failure at any past moment.
//
// Honesty contract (the S43 watch-out): simulation accuracy depends on graph
// completeness, so every Impact carries a Coverage block reporting which
// planes contributed edges and which linkages are absent. The simulator never
// guesses across missing planes. SLO impact attaches via the SLOSource seam
// (the S45 engine plugs in; absent = reported, not silently empty).
//
// The simulator runs on a Snapshot, so it works identically over any Store
// implementation — the dedicated-engine migration is transparent to it.

import (
	"fmt"
	"sort"
	"time"
)

// SLOSource maps impacted services/hosts onto the SLOs they back (S45).
type SLOSource interface {
	ImpactedSLOs(tenant string, serviceIDs, hostIDs []string) []string
}

// PathImpact is one agent→target path affected by the simulated failure.
type PathImpact struct {
	From     string   `json:"from"` // agent node id
	To       string   `json:"to"`   // host/target node id
	Status   string   `json:"status"`
	Route    []string `json:"route"`               // the pre-failure route through the failed element
	AltRoute []string `json:"alt_route,omitempty"` // the surviving route (status "rerouted")
}

// Path impact classifications.
const (
	PathBroken   = "broken"   // no surviving route
	PathRerouted = "rerouted" // an alternate route survives
)

// Coverage reports what the graph actually contained at simulation time —
// the honesty block (accuracy depends on completeness).
type Coverage struct {
	PathEdges    int      `json:"path_edges"`
	FlowEdges    int      `json:"flow_edges"`
	RoutingEdges int      `json:"routing_edges"`
	DeviceEdges  int      `json:"device_edges"`
	Notes        []string `json:"notes,omitempty"`
}

// Impact is the simulation result for one failed element.
type Impact struct {
	Target           string       `json:"target"`
	TargetKind       string       `json:"target_kind"` // node kind, or "edge"
	At               time.Time    `json:"at"`
	BrokenPaths      []PathImpact `json:"broken_paths"`
	ReroutedPaths    []PathImpact `json:"rerouted_paths"`
	ImpactedServices []string     `json:"impacted_services"`
	ImpactedPrefixes []string     `json:"impacted_prefixes"`
	Disconnected     []string     `json:"disconnected"` // newly unreachable from every agent
	ImpactedSLOs     []string     `json:"impacted_slos"`
	Coverage         Coverage     `json:"coverage"`
}

// Simulate fails the element with id `target` (a node ID like "hop:10.0.0.1"
// or an edge ID "from|kind|to") in tenant's graph as it was at `at` — a zero
// `at` simulates over the LIVE graph (everything currently known) — and
// returns the predicted impact. Unknown targets are an error (fail closed —
// a typo'd simulation must not return an empty "no impact").
func Simulate(s Store, tenant, target string, at time.Time, slo SLOSource) (Impact, error) {
	graph, err := s.ForTenant(tenant)
	if err != nil {
		return Impact{}, err
	}
	var snap Snapshot
	if at.IsZero() {
		snap = graph.Latest()
		at = snap.At
	} else {
		snap = graph.SnapshotAt(at)
	}
	sim := newSimGraph(snap)

	imp := Impact{Target: target, At: at}
	failedNode, isNode := sim.nodes[target]
	_, isEdge := sim.edges[target]
	switch {
	case isNode:
		imp.TargetKind = string(failedNode.Kind)
	case isEdge:
		imp.TargetKind = "edge"
	default:
		return Impact{}, fmt.Errorf("topology: unknown node or edge %q at %s", target, at.UTC().Format(time.RFC3339))
	}

	imp.Coverage = sim.coverage()

	// --- path plane: every agent→host route, before vs after the failure ---
	before := sim.adjacency(EdgePath, false, "")
	after := sim.adjacency(EdgePath, false, target)
	for _, agent := range sim.nodesOfKind(NodeAgent) {
		if agent.ID == target {
			// The agent itself failed: every route it had is broken.
			for host, route := range routesFrom(before, agent.ID, sim, NodeHost) {
				imp.BrokenPaths = append(imp.BrokenPaths, PathImpact{
					From: agent.ID, To: host, Status: PathBroken, Route: route,
				})
			}
			continue
		}
		preRoutes := routesFrom(before, agent.ID, sim, NodeHost)
		for host, route := range preRoutes {
			if !routeUses(route, target) {
				continue
			}
			if alt := bfsRoute(after, agent.ID, host); alt != nil {
				imp.ReroutedPaths = append(imp.ReroutedPaths, PathImpact{
					From: agent.ID, To: host, Status: PathRerouted, Route: route, AltRoute: alt,
				})
			} else {
				imp.BrokenPaths = append(imp.BrokenPaths, PathImpact{
					From: agent.ID, To: host, Status: PathBroken, Route: route,
				})
			}
		}
	}
	sortPathImpacts(imp.BrokenPaths)
	sortPathImpacts(imp.ReroutedPaths)

	// --- service plane: transitive callers of a failed service lose their
	// dependency (reverse reachability over flow edges) ---
	if isNode && (failedNode.Kind == NodeService || failedNode.Kind == NodeHost) {
		rev := sim.adjacency(EdgeFlow, true, "")
		callers := reachableFrom(rev, target)
		delete(callers, target)
		for c := range callers {
			imp.ImpactedServices = append(imp.ImpactedServices, c)
		}
		if failedNode.Kind == NodeService {
			imp.ImpactedServices = append(imp.ImpactedServices, target)
		}
		sort.Strings(imp.ImpactedServices)
	}

	// --- routing plane: prefixes originated by a failed AS; a failed prefix
	// is its own impact ---
	if isNode {
		switch failedNode.Kind {
		case NodeAS:
			fwd := sim.adjacency(EdgeRouting, false, "")
			for pfx := range fwd[target] {
				imp.ImpactedPrefixes = append(imp.ImpactedPrefixes, pfx)
			}
		case NodePrefix:
			imp.ImpactedPrefixes = append(imp.ImpactedPrefixes, target)
		}
		sort.Strings(imp.ImpactedPrefixes)
	}

	// --- global disconnections: reachable from any agent before, none after
	// (all planes, undirected — "what falls off the map") ---
	allBefore := sim.adjacency("", false, "")
	allAfter := sim.adjacency("", false, target)
	pre := map[string]bool{}
	post := map[string]bool{}
	for _, agent := range sim.nodesOfKind(NodeAgent) {
		if agent.ID == target {
			continue
		}
		for n := range reachableFrom(undirect(allBefore), agent.ID) {
			pre[n] = true
		}
		for n := range reachableFrom(undirect(allAfter), agent.ID) {
			post[n] = true
		}
	}
	for n := range pre {
		if !post[n] && n != target {
			imp.Disconnected = append(imp.Disconnected, n)
		}
	}
	sort.Strings(imp.Disconnected)

	// --- SLO impact (S45 seam) ---
	if slo != nil {
		hosts := make([]string, 0, len(imp.BrokenPaths))
		for _, p := range imp.BrokenPaths {
			hosts = append(hosts, p.To)
		}
		imp.ImpactedSLOs = slo.ImpactedSLOs(tenant, imp.ImpactedServices, hosts)
	} else {
		imp.Coverage.Notes = append(imp.Coverage.Notes,
			"slo impact not wired (S45) — paths/services only")
	}

	// Never-nil slices: the API renders honest empties, not nulls.
	for _, p := range []*[]PathImpact{&imp.BrokenPaths, &imp.ReroutedPaths} {
		if *p == nil {
			*p = []PathImpact{}
		}
	}
	for _, l := range []*[]string{&imp.ImpactedServices, &imp.ImpactedPrefixes, &imp.Disconnected, &imp.ImpactedSLOs} {
		if *l == nil {
			*l = []string{}
		}
	}
	return imp, nil
}

// --- simulation graph helpers ---

type simGraph struct {
	nodes map[string]Node
	edges map[string]Edge
}

func newSimGraph(s Snapshot) *simGraph {
	g := &simGraph{nodes: make(map[string]Node, len(s.Nodes)), edges: make(map[string]Edge, len(s.Edges))}
	for _, n := range s.Nodes {
		g.nodes[n.ID] = n
	}
	for _, e := range s.Edges {
		g.edges[e.ID] = e
	}
	return g
}

func (g *simGraph) nodesOfKind(k NodeKind) []Node {
	var out []Node
	for _, n := range g.nodes {
		if n.Kind == k {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// adjacency builds kind-filtered adjacency (kind "" = all), reversed when
// rev, excluding the failed node/edge id.
func (g *simGraph) adjacency(kind EdgeKind, rev bool, failed string) map[string]map[string]bool {
	adj := map[string]map[string]bool{}
	add := func(a, b string) {
		if adj[a] == nil {
			adj[a] = map[string]bool{}
		}
		adj[a][b] = true
	}
	for id, e := range g.edges {
		if kind != "" && e.Kind != kind {
			continue
		}
		if id == failed || e.From == failed || e.To == failed {
			continue
		}
		if rev {
			add(e.To, e.From)
		} else {
			add(e.From, e.To)
		}
	}
	return adj
}

func (g *simGraph) coverage() Coverage {
	var c Coverage
	for _, e := range g.edges {
		c.count(e.Kind)
	}
	c.annotate()
	return c
}

// SnapshotCoverage reports a snapshot's per-plane edge coverage with the
// same honesty notes the simulator attaches — the UI shows the operator what
// the graph actually contains before they trust a simulation.
func SnapshotCoverage(s Snapshot) Coverage {
	var c Coverage
	for _, e := range s.Edges {
		c.count(e.Kind)
	}
	c.annotate()
	return c
}

func (c *Coverage) count(k EdgeKind) {
	switch k {
	case EdgePath:
		c.PathEdges++
	case EdgeFlow:
		c.FlowEdges++
	case EdgeRouting:
		c.RoutingEdges++
	case EdgeDevice:
		c.DeviceEdges++
	}
}

func (c *Coverage) annotate() {
	if c.FlowEdges == 0 {
		c.Notes = append(c.Notes, "no flow-plane (eBPF) edges — service impact may be incomplete")
	}
	if c.RoutingEdges == 0 {
		c.Notes = append(c.Notes, "no routing-plane (BGP) edges — prefix impact may be incomplete")
	}
	if c.DeviceEdges == 0 {
		c.Notes = append(c.Notes, "no device→hop interface links — device-level impact unavailable")
	}
}

// routesFrom returns the BFS route from start to every reachable node of the
// wanted kind: target node id → route (node ids, start..target).
func routesFrom(adj map[string]map[string]bool, start string, g *simGraph, want NodeKind) map[string][]string {
	parent := bfsParents(adj, start)
	out := map[string][]string{}
	for id := range parent {
		if n, ok := g.nodes[id]; ok && n.Kind == want && id != start {
			out[id] = rebuild(parent, start, id)
		}
	}
	return out
}

// bfsRoute returns one shortest route start→goal, or nil.
func bfsRoute(adj map[string]map[string]bool, start, goal string) []string {
	parent := bfsParents(adj, start)
	if _, ok := parent[goal]; !ok {
		return nil
	}
	return rebuild(parent, start, goal)
}

// bfsParents runs BFS and returns the parent map (start maps to itself).
func bfsParents(adj map[string]map[string]bool, start string) map[string]string {
	parent := map[string]string{start: start}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		// Deterministic order keeps routes (and tests) stable.
		next := make([]string, 0, len(adj[cur]))
		for n := range adj[cur] {
			next = append(next, n)
		}
		sort.Strings(next)
		for _, n := range next {
			if _, seen := parent[n]; !seen {
				parent[n] = cur
				queue = append(queue, n)
			}
		}
	}
	return parent
}

func rebuild(parent map[string]string, start, goal string) []string {
	var route []string
	for cur := goal; ; cur = parent[cur] {
		route = append(route, cur)
		if cur == start {
			break
		}
	}
	for i, j := 0, len(route)-1; i < j; i, j = i+1, j-1 {
		route[i], route[j] = route[j], route[i]
	}
	return route
}

// reachableFrom returns every node reachable from start (incl. start).
func reachableFrom(adj map[string]map[string]bool, start string) map[string]bool {
	seen := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for n := range adj[cur] {
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	return seen
}

func undirect(adj map[string]map[string]bool) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(a, b string) {
		if out[a] == nil {
			out[a] = map[string]bool{}
		}
		out[a][b] = true
	}
	for a, ns := range adj {
		for b := range ns {
			add(a, b)
			add(b, a)
		}
	}
	return out
}

// routeUses reports whether the route traverses the failed node or edge id.
func routeUses(route []string, failed string) bool {
	for i, n := range route {
		if n == failed {
			return true
		}
		if i+1 < len(route) {
			// Any edge kind between consecutive route nodes — route edges are
			// path edges by construction.
			if EdgeID(route[i], EdgePath, route[i+1]) == failed {
				return true
			}
		}
	}
	return false
}

func sortPathImpacts(ps []PathImpact) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].From != ps[j].From {
			return ps[i].From < ps[j].From
		}
		return ps[i].To < ps[j].To
	})
}
