package topology

import "time"

// NodeKind classifies a topology node.
type NodeKind string

const (
	NodeAgent   NodeKind = "agent"
	NodeHop     NodeKind = "hop"     // a traceroute responder (router / L3 hop)
	NodeHost    NodeKind = "host"    // a probed host / path target
	NodeService NodeKind = "service" // an eBPF service / workload
	NodePrefix  NodeKind = "prefix"  // a BGP prefix
	NodeAS      NodeKind = "as"      // an autonomous system
)

// EdgeKind classifies a topology edge.
type EdgeKind string

const (
	EdgePath    EdgeKind = "path"    // traceroute adjacency (hop -> hop)
	EdgeFlow    EdgeKind = "flow"    // eBPF service edge (service -> service)
	EdgeRouting EdgeKind = "routing" // BGP origin (as -> prefix)
)

// Node is a vertex in the topology graph, valid over [FirstSeen, LastSeen].
type Node struct {
	ID         string
	Kind       NodeKind
	Label      string
	Attributes map[string]string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Edge is a directed edge, valid over [FirstSeen, LastSeen].
type Edge struct {
	ID         string
	From       string
	To         string
	Kind       EdgeKind
	Label      string
	Attributes map[string]string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Snapshot is the graph, or a temporal slice of it, at a point in time.
type Snapshot struct {
	Tenant string
	At     time.Time
	Nodes  []Node
	Edges  []Edge
}

// EdgeID is the canonical id of a directed edge of a kind.
func EdgeID(from string, kind EdgeKind, to string) string {
	return from + "|" + string(kind) + "|" + to
}
