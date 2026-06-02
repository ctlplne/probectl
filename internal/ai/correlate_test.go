package ai

import (
	"context"
	"testing"
)

func TestCorrelateFansOutAndRespectsRBAC(t *testing.T) {
	metrics := newRecordingSource(map[string][]Row{"t": {{"metric": "rtt"}}})
	events := newRecordingSource(map[string][]Row{"t": {{"event": "loss"}}})
	topo := newRecordingSource(map[string][]Row{"t": {{"node": "service:checkout"}}})

	// The caller may read metrics + topology, NOT events / entities.
	e := NewEngine(WithMetrics(metrics), WithEvents(events), WithTopology(topo))
	p := principal("t", PermMetricsRead, PermTopologyRead)

	res, err := e.Correlate(context.Background(), p, map[string]string{"service": "checkout"}, TimeRange{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[Domain]bool{}
	for _, d := range res.Domains {
		got[d] = true
	}
	if !got[DomainMetrics] || !got[DomainTopology] || got[DomainEvents] {
		t.Errorf("provenance = %v, want metrics + topology only (events RBAC-skipped)", res.Domains)
	}
	if len(events.seen()) != 0 {
		t.Error("events source was queried despite the caller lacking events.read")
	}
	for _, row := range res.Rows {
		if row["_domain"] == nil {
			t.Errorf("row missing _domain provenance: %v", row)
		}
	}
}
