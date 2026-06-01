package topology

import (
	"testing"
	"time"
)

func TestToViz(t *testing.T) {
	g := NewGraph("t1")
	at := time.Unix(0, 0)
	g.ObserveServiceEdge(ServiceEdgeInput{Source: "a", Destination: "b", DestPort: 80, Transport: "tcp"}, at)

	v := ToViz(g.Latest())
	if v.Tenant != "t1" || len(v.Nodes) != 2 || len(v.Edges) != 1 {
		t.Fatalf("viz = %+v", v)
	}
	if v.Edges[0].Kind != string(EdgeFlow) {
		t.Errorf("edge kind = %q, want flow", v.Edges[0].Kind)
	}
}
