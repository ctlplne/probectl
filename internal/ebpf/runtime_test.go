// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"

	"github.com/ctlplne/probectl/internal/ebpf/l7"
)

// sliceSource is an in-memory Source over a fixed slice of flows.
type sliceSource struct {
	flows     []Flow
	drops     uint64
	dropStats DropStats
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
func (s *sliceSource) Drops() uint64 {
	if s.dropStats.Total() > 0 {
		return s.dropStats.Total()
	}
	return s.drops
}
func (s *sliceSource) DropStats() DropStats {
	if s.dropStats.Total() > 0 {
		return s.dropStats
	}
	return DropStats{Other: s.drops}
}
func (s *sliceSource) Close() error { return nil }

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

type sliceL7Source struct {
	events    []L7Event
	dropStats DropStats
}

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
func (s *sliceL7Source) Drops() uint64        { return s.dropStats.Total() }
func (s *sliceL7Source) DropStats() DropStats { return s.dropStats }
func (s *sliceL7Source) Close() error         { return nil }

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

func TestAgentRunReportsDetailedKernelDrops(t *testing.T) {
	src := &sliceSource{dropStats: DropStats{
		DecodeFailures:   1,
		L4RingBufferFull: 3,
	}}
	l7src := &sliceL7Source{dropStats: DropStats{
		L7RingBufferFull:     2,
		L7ActiveReadFailures: 4,
		L7ScopeSyncFailures:  6,
	}}
	em := &captureEmitter{}
	cfg := &Config{TenantID: "t1", Host: "h", FlushInterval: time.Hour}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), src, NopEnricher{}, em)
	a.l7source = l7src

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	st := a.agg.Stats()
	if st.Dropped != 16 {
		t.Fatalf("dropped_total = %d, want 16", st.Dropped)
	}
	if st.DecodeFailures != 1 || st.L4RingBufferFull != 3 || st.L7RingBufferFull != 2 || st.L7ActiveReadFailures != 4 || st.L7ScopeSyncFailures != 6 {
		t.Fatalf("drop stats = %+v, want decode=1 l4_ring=3 l7_ring=2 active_reads=4 scope_sync=6", st.DropStats)
	}
}

func TestAgentSyncsDropStatsAsDeltas(t *testing.T) {
	src := &sliceSource{}
	cfg := &Config{TenantID: "t1", Host: "h", FlushInterval: time.Hour}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), src, NopEnricher{}, &captureEmitter{})

	src.dropStats = DropStats{L4RingBufferFull: 2}
	if !a.syncDrops() {
		t.Fatal("first sync should report changed counters")
	}
	src.dropStats = DropStats{L4RingBufferFull: 5, L7ActiveReadFailures: 1, L7ScopeSyncFailures: 2}
	if !a.syncDrops() {
		t.Fatal("second sync should report changed counters")
	}
	if a.syncDrops() {
		t.Fatal("unchanged counters should not report a change")
	}

	st := a.agg.Stats()
	if st.Dropped != 8 || st.L4RingBufferFull != 5 || st.L7ActiveReadFailures != 1 || st.L7ScopeSyncFailures != 2 {
		t.Fatalf("stats after deltas = %+v, want dropped=8 l4_ring=5 active_reads=1 scope_sync=2", st)
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

// verifyingBus is an asynchronous bus: Publish accepts every record, and the
// rejection (if any) only ever shows up in the failure counters or as a flush
// error — exactly how the Kafka bus behaves (DPR-071).
type verifyingBus struct {
	publishes int
	rejectAll bool // every accepted record is reported failed afterwards
	flushErr  error
	failed    uint64
}

func (v *verifyingBus) Publish(context.Context, string, []byte, []byte) error {
	v.publishes++
	if v.rejectAll {
		v.failed++
	}
	return nil
}
func (v *verifyingBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (v *verifyingBus) Close() error                                                 { return nil }
func (v *verifyingBus) Flush(context.Context) error                                  { return v.flushErr }
func (v *verifyingBus) PublishFailures() (uint64, uint64, error) {
	if v.failed == 0 {
		return 0, 0, nil
	}
	return v.failed, 0, errors.New("last produce failure on probectl.t-acme.ebpf.flows: MESSAGE_TOO_LARGE (uncompressed_bytes=1048600)")
}

func newVerifyingAgent(t *testing.T, vb *verifyingBus, logs *bytes.Buffer) *Agent {
	t.Helper()
	cfg := &Config{TenantID: "t1", Host: "node-1", FlushInterval: time.Hour, MaxBatchBytes: DefaultMaxBatchBytes}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(logs, nil)), &sliceSource{}, NopEnricher{}, NewBusEmitter(vb, "t1"))
	a.withPublishVerification(vb, time.Second)
	a.ready.Store(true) // as if the flow source were streaming
	return a
}

func observeOne(a *Agent, port uint32) {
	a.observe(Flow{Source: Endpoint{Address: "10.0.0.1"}, Destination: Endpoint{Address: "10.0.0.2", Port: port}, Transport: "tcp"})
}

// DPR-071: on the lab every batch after the first 22 was rejected by the bus
// (MESSAGE_TOO_LARGE) for hours while the agent logged "ebpf flows emitted"
// with dropped_total=0. The agent now confirms delivery after every emit: a
// record the bus reports undelivered is logged at ERROR with the bus's reason,
// counted, and takes readiness down until a flush delivers cleanly.
func TestAgentFlushSurfacesAsyncPublishRejections(t *testing.T) {
	var logs bytes.Buffer
	vb := &verifyingBus{rejectAll: true}
	a := newVerifyingAgent(t, vb, &logs)

	observeOne(a, 443)
	a.flush(context.Background())
	if vb.publishes != 1 {
		t.Fatalf("publishes = %d, want 1", vb.publishes)
	}
	if got := a.PublishFailures(); got != 1 {
		t.Errorf("PublishFailures = %d, want 1", got)
	}
	if !a.PublishDegraded() || a.Ready() {
		t.Errorf("degraded=%v ready=%v; an undelivered flush must take readiness down", a.PublishDegraded(), a.Ready())
	}
	out := logs.String()
	if !strings.Contains(out, "ebpf publish FAILED") || !strings.Contains(out, "MESSAGE_TOO_LARGE") {
		t.Errorf("the rejection and its reason must be logged at ERROR, got:\n%s", out)
	}
	if strings.Contains(out, "ebpf flows emitted") {
		t.Errorf("a rejected flush must not be reported as emitted:\n%s", out)
	}

	// The next flush delivers cleanly: readiness recovers, the counter keeps history.
	vb.rejectAll = false
	logs.Reset()
	observeOne(a, 8443)
	a.flush(context.Background())
	if a.PublishDegraded() || !a.Ready() {
		t.Errorf("degraded=%v ready=%v after a clean flush", a.PublishDegraded(), a.Ready())
	}
	if got := a.PublishFailures(); got != 1 {
		t.Errorf("PublishFailures = %d after recovery, want the historical 1", got)
	}
	if !strings.Contains(logs.String(), "ebpf flows emitted") || !strings.Contains(logs.String(), "publish_batches_total=1") {
		t.Errorf("a delivered flush is reported with its publish counters, got:\n%s", logs.String())
	}
}

func TestAgentFlushSurfacesUnacknowledgedPublish(t *testing.T) {
	var logs bytes.Buffer
	vb := &verifyingBus{flushErr: context.DeadlineExceeded}
	a := newVerifyingAgent(t, vb, &logs)
	observeOne(a, 443)
	a.flush(context.Background())
	if got := a.PublishFailures(); got != 1 || !a.PublishDegraded() || a.Ready() {
		t.Errorf("failures=%d degraded=%v ready=%v; an unacknowledged flush must be surfaced", got, a.PublishDegraded(), a.Ready())
	}
	if !strings.Contains(logs.String(), "ebpf publish NOT acknowledged") {
		t.Errorf("expected the unacknowledged-publish error, got:\n%s", logs.String())
	}
}

func TestPublishVerifyTimeoutIsBounded(t *testing.T) {
	for _, tc := range []struct {
		in, want time.Duration
	}{
		{10 * time.Second, 5 * time.Second},
		{2 * time.Second, time.Second},
		{time.Hour, 5 * time.Second},
		{0, 5 * time.Second},
	} {
		if got := publishVerifyTimeout(tc.in); got != tc.want {
			t.Errorf("publishVerifyTimeout(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
