package ai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/topology"
)

func TestTopologySourceNeighborsAndSnapshot(t *testing.T) {
	store := topology.NewMemoryStore()
	at := time.Unix(100, 0)
	store.ObserveServiceEdge("t", topology.ServiceEdgeInput{Source: "a", Destination: "b", DestPort: 80, Transport: "tcp"}, at)
	e := NewEngine(WithTopology(NewTopologySource(store)))
	p := principal("t", PermTopologyRead)

	nbr, err := e.Query(context.Background(), p, Query{Domain: DomainTopology, NodeID: "service:a", Range: TimeRange{At: at}})
	if err != nil {
		t.Fatal(err)
	}
	if len(nbr.Rows) != 1 {
		t.Errorf("neighbors(service:a) = %v, want 1 (service:b)", nbr.Rows)
	}

	snap, err := e.Query(context.Background(), p, Query{Domain: DomainTopology, Range: TimeRange{At: at}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Rows) != 2 {
		t.Errorf("snapshot@at = %d nodes, want 2", len(snap.Rows))
	}
}

type erroringMetrics struct{}

func (erroringMetrics) QueryMetrics(context.Context, string, map[string]string, TimeRange, int) ([]Row, error) {
	return nil, errors.New("boom")
}

func TestCorrelatePropagatesSourceError(t *testing.T) {
	e := NewEngine(WithMetrics(erroringMetrics{}))
	if _, err := e.Correlate(context.Background(), principal("t", PermMetricsRead), nil, TimeRange{}); err == nil {
		t.Error("a source error should propagate from Correlate")
	}
}

func TestEngineZeroOptionsAreNoOps(t *testing.T) {
	e := NewEngine(WithMaxRows(0), WithTimeout(0))
	if e.maxRows != 1000 || e.timeout != 30*time.Second {
		t.Errorf("zero options should be no-ops: maxRows=%d timeout=%v", e.maxRows, e.timeout)
	}
}
