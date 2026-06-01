package ebpf

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// sliceSource is an in-memory Source over a fixed slice of flows.
type sliceSource struct {
	flows []Flow
	drops uint64
}

func (s *sliceSource) Flows(ctx context.Context) (<-chan Flow, error) {
	ch := make(chan Flow)
	go func() {
		defer close(ch)
		for _, f := range s.flows {
			select {
			case <-ctx.Done():
				return
			case ch <- f:
			}
		}
	}()
	return ch, nil
}
func (s *sliceSource) Drops() uint64 { return s.drops }
func (s *sliceSource) Close() error  { return nil }

type captureEmitter struct {
	flows []Flow
	edges []ServiceEdge
	calls int
}

func (c *captureEmitter) Emit(_ context.Context, f []Flow, e []ServiceEdge) error {
	c.flows = append(c.flows, f...)
	c.edges = e
	c.calls++
	return nil
}

func TestAgentRunEmitsFlowsAndEdges(t *testing.T) {
	src := &sliceSource{flows: []Flow{
		{Source: Endpoint{Address: "10.0.0.1", Workload: "api"}, Destination: Endpoint{Address: "10.0.0.2", Port: 443, Workload: "db"}, Transport: "tcp"},
		{Source: Endpoint{Address: "10.0.0.1", Workload: "api"}, Destination: Endpoint{Address: "10.0.0.2", Port: 443, Workload: "db"}, Transport: "tcp"},
	}}
	em := &captureEmitter{}
	cfg := &Config{TenantID: "t1", Host: "node-1", FlushInterval: time.Hour} // final flush is on source exhaustion
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := newAgentWith(cfg, log, src, NopEnricher{}, em)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}

	if em.calls == 0 {
		t.Fatal("emitter never called")
	}
	if len(em.flows) != 2 {
		t.Errorf("emitted flows = %d, want 2", len(em.flows))
	}
	if len(em.edges) != 1 || em.edges[0].Connections != 2 {
		t.Errorf("edges = %+v, want 1 edge conns=2", em.edges)
	}
	for _, f := range em.flows {
		if f.TenantID != "t1" {
			t.Errorf("flow tenant = %q, want t1 (stamped by runtime)", f.TenantID)
		}
	}
}

func TestAgentRunReportsDrops(t *testing.T) {
	src := &sliceSource{
		flows: []Flow{{Source: Endpoint{Address: "10.0.0.1"}, Destination: Endpoint{Address: "10.0.0.2", Port: 80}, Transport: "tcp"}},
		drops: 5,
	}
	em := &captureEmitter{}
	cfg := &Config{TenantID: "t1", Host: "h", FlushInterval: time.Hour}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), src, NopEnricher{}, em)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := a.agg.Stats().Dropped; got != 5 {
		t.Errorf("dropped_total = %d, want 5 (ring-buffer drops surfaced)", got)
	}
}
