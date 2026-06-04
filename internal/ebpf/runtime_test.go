package ebpf

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
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
	l7    []L7Record
	calls int
}

func (c *captureEmitter) Emit(_ context.Context, f []Flow, e []ServiceEdge, l7calls []L7Record) error {
	c.flows = append(c.flows, f...)
	c.edges = e
	c.l7 = append(c.l7, l7calls...)
	c.calls++
	return nil
}

type sliceL7Source struct{ events []L7Event }

func (s *sliceL7Source) L7Events(ctx context.Context) (<-chan L7Event, error) {
	ch := make(chan L7Event)
	go func() {
		defer close(ch)
		for _, e := range s.events {
			select {
			case <-ctx.Done():
				return
			case ch <- e:
			}
		}
	}()
	return ch, nil
}
func (s *sliceL7Source) Drops() uint64 { return 0 }
func (s *sliceL7Source) Close() error  { return nil }

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

func TestAgentRunEmitsL7Calls(t *testing.T) {
	t0 := time.Unix(0, 0)
	reqHdr := func(line string) []byte { return []byte(line + "\r\nContent-Length: 0\r\n\r\n") }
	srcEP := Endpoint{Workload: "checkout"}
	dstEP := Endpoint{Workload: "orders", Port: 8443}
	l7src := &sliceL7Source{events: []L7Event{
		{ConnID: 1, TenantID: "t1", Source: srcEP, Destination: dstEP, Transport: "tcp", Encrypted: true, Data: l7.DataEvent{Kind: l7.Request, Time: t0, Payload: reqHdr("GET /orders/42 HTTP/1.1")}},
		{ConnID: 1, Data: l7.DataEvent{Kind: l7.Response, Time: t0.Add(12 * time.Millisecond), Payload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")}},
		{ConnID: 1, TenantID: "t1", Source: srcEP, Destination: dstEP, Transport: "tcp", Encrypted: true, Data: l7.DataEvent{Kind: l7.Request, Time: t0.Add(20 * time.Millisecond), Payload: reqHdr("POST /orders HTTP/1.1")}},
		{ConnID: 1, Data: l7.DataEvent{Kind: l7.Response, Time: t0.Add(58 * time.Millisecond), Payload: []byte("HTTP/1.1 500 err\r\nContent-Length: 0\r\n\r\n")}},
	}}
	em := &captureEmitter{}
	cfg := &Config{TenantID: "t1", Host: "node-1", FlushInterval: time.Hour}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &sliceSource{}, NopEnricher{}, em)
	a.l7source = l7src

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}

	if len(em.l7) != 2 {
		t.Fatalf("emitted l7 calls = %d, want 2", len(em.l7))
	}
	for _, r := range em.l7 {
		if r.Source.ID() != "checkout" || r.Destination.ID() != "orders" || !r.Encrypted {
			t.Errorf("l7 record misattributed to the request-direction edge: %+v", r)
		}
	}

	var edge *ServiceEdge
	for i := range em.edges {
		if em.edges[i].Source == "checkout" && em.edges[i].Destination == "orders" {
			edge = &em.edges[i]
		}
	}
	if edge == nil || edge.L7Calls != 2 || edge.L7Errors != 1 || edge.L7Protocol != "http1" {
		t.Errorf("edge L7 rollup = %+v", edge)
	}
}
