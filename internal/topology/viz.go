package topology

import "time"

// VizNode, VizEdge, and Viz are the basic visualization shape S43's topology view
// (and the UI) render. It is layout-agnostic — node positions are computed
// client-side from the node/edge set.
type VizNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type VizEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Label string `json:"label,omitempty"`
}

type Viz struct {
	Tenant string    `json:"tenant"`
	At     time.Time `json:"at"`
	Nodes  []VizNode `json:"nodes"`
	Edges  []VizEdge `json:"edges"`
}

// ToViz projects a snapshot to the visualization shape.
func ToViz(s Snapshot) Viz {
	v := Viz{
		Tenant: s.Tenant,
		At:     s.At,
		Nodes:  make([]VizNode, 0, len(s.Nodes)),
		Edges:  make([]VizEdge, 0, len(s.Edges)),
	}
	for _, n := range s.Nodes {
		v.Nodes = append(v.Nodes, VizNode{ID: n.ID, Kind: string(n.Kind), Label: n.Label})
	}
	for _, e := range s.Edges {
		v.Edges = append(v.Edges, VizEdge{From: e.From, To: e.To, Kind: string(e.Kind), Label: e.Label})
	}
	return v
}
