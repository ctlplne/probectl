// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/topology"
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
	if len(nbr.Rows) < 2 {
		t.Errorf("neighbors(service:a) = %v, want node plus service:b edge", nbr.Rows)
	}
	for _, row := range nbr.Rows {
		if row["plane"] != "topology" {
			t.Fatalf("topology row missing plane marker: %+v", row)
		}
	}

	store.ObserveRouting("t", topology.RoutingInput{Prefix: "192.0.2.0/24", OriginASN: 64500}, at)
	prefix, err := e.Query(context.Background(), p, Query{Domain: DomainTopology, NodeID: "prefix:192.0.2.0/24", Range: TimeRange{At: at}})
	if err != nil {
		t.Fatal(err)
	}
	if len(prefix.Rows) < 2 {
		t.Fatalf("topology prefix evidence = %v, want node plus incoming routing edge", prefix.Rows)
	}
	for _, row := range prefix.Rows {
		if row["plane"] != "topology" {
			t.Fatalf("topology row missing plane marker: %+v", row)
		}
	}

	snap, err := e.Query(context.Background(), p, Query{Domain: DomainTopology, Range: TimeRange{At: at}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Rows) != 4 {
		t.Errorf("snapshot@at = %d nodes, want 4", len(snap.Rows))
	}
}

type erroringMetrics struct{}

func (erroringMetrics) QueryMetrics(context.Context, string, map[string]string, TimeRange, int) ([]Row, error) {
	return nil, errors.New("boom")
}

func TestCorrelatePropagatesSourceError(t *testing.T) {
	e := NewEngine(WithMetrics(erroringMetrics{}))
	if _, err := e.correlate(context.Background(), principal("t", PermMetricsRead), nil, TimeRange{}); err == nil {
		t.Error("a source error should propagate from Correlate")
	}
}

func TestEngineZeroOptionsAreNoOps(t *testing.T) {
	e := NewEngine(WithMaxRows(0), withTimeout(0))
	if e.maxRows != 1000 || e.timeout != 30*time.Second {
		t.Errorf("zero options should be no-ops: maxRows=%d timeout=%v", e.maxRows, e.timeout)
	}
}
