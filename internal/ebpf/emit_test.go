// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/ebpf/l7"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
)

// fakeBus captures the last Publish for assertions (no timing/goroutines).
type fakeBus struct {
	topic string
	key   []byte
	value []byte
	calls int
}

func (f *fakeBus) Publish(_ context.Context, topic string, key, value []byte) error {
	f.topic, f.key, f.value = topic, key, value
	f.calls++
	return nil
}
func (f *fakeBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (f *fakeBus) Close() error                                                 { return nil }

func TestBusEmitterMarshalsAndPublishes(t *testing.T) {
	fb := &fakeBus{}
	em := NewBusEmitter(fb, "t1")
	flows := []Flow{{TenantID: "t1", Source: Endpoint{Address: "10.0.0.1", Port: 5}, Destination: Endpoint{Address: "10.0.0.2", Port: 443}, Transport: "tcp"}}
	edges := []ServiceEdge{{TenantID: "t1", Source: "10.0.0.1", Destination: "10.0.0.2", DestPort: 443, Transport: "tcp", Connections: 1}}
	l7calls := []L7Record{{TenantID: "t1", Source: Endpoint{Workload: "api"}, Destination: Endpoint{Workload: "db", Port: 443}, Encrypted: true, Call: l7.Call{Protocol: "http1", Method: "GET", Resource: "/x", Status: "200"}}}

	if err := em.Emit(context.Background(), flows, edges, l7calls); err != nil {
		t.Fatal(err)
	}
	if fb.topic != bus.EBPFFlowsTopic {
		t.Errorf("topic = %q, want %q", fb.topic, bus.EBPFFlowsTopic)
	}
	if string(fb.key) != "t1" {
		t.Errorf("key = %q, want tenant t1 (pooled tagging)", fb.key)
	}

	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(fb.value, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Flows) != 1 || batch.Flows[0].GetSourcePort() != 5 || batch.Flows[0].GetDestinationPort() != 443 {
		t.Errorf("flows = %+v", batch.Flows)
	}
	if len(batch.Edges) != 1 || batch.Edges[0].GetConnections() != 1 {
		t.Errorf("edges = %+v", batch.Edges)
	}
	if len(batch.L7Calls) != 1 || batch.L7Calls[0].GetProtocol() != "http1" || !batch.L7Calls[0].GetEncrypted() {
		t.Errorf("l7 calls = %+v", batch.L7Calls)
	}
}

func TestBusEmitterEmptyBatchIsNoop(t *testing.T) {
	fb := &fakeBus{}
	if err := NewBusEmitter(fb, "t1").Emit(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if fb.calls != 0 {
		t.Error("empty batch must not publish")
	}
}

// recordingBus keeps every published record (DPR-071: a flush may leave as
// several records).
type recordingBus struct {
	keys   [][]byte
	values [][]byte
}

func (r *recordingBus) Publish(_ context.Context, _ string, key, value []byte) error {
	r.keys = append(r.keys, key)
	r.values = append(r.values, value)
	return nil
}
func (r *recordingBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (r *recordingBus) Close() error                                                 { return nil }

func syntheticFlush(nFlows, nEdges, nL7 int) ([]Flow, []ServiceEdge, []L7Record) {
	flows := make([]Flow, nFlows)
	for i := range flows {
		flows[i] = Flow{TenantID: "t1", AgentID: "agent-1", Host: "node-1",
			Source:      Endpoint{Address: "10.0.0.1", Port: uint32(1024 + i), Process: "curl", Workload: "checkout"},
			Destination: Endpoint{Address: "10.0.0.2", Port: 443, Workload: "payments"},
			Transport:   "tcp", Bytes: 512, Packets: 4}
	}
	edges := make([]ServiceEdge, nEdges)
	for i := range edges {
		edges[i] = ServiceEdge{TenantID: "t1", Source: "10.0." + itoa(i/250) + "." + itoa(i%250),
			Destination: "10.1.0.1", DestPort: 443, Transport: "tcp", Connections: uint64(i + 1), Bytes: 1024}
	}
	l7calls := make([]L7Record, nL7)
	for i := range l7calls {
		l7calls[i] = L7Record{TenantID: "t1", Source: Endpoint{Workload: "api"}, Destination: Endpoint{Workload: "db", Port: 443},
			Call: l7.Call{Protocol: "http1", Method: "GET", Resource: "/orders/" + itoa(i), Status: "200"}}
	}
	return flows, edges, l7calls
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }

func decodeRecords(t *testing.T, values [][]byte) []*ebpfv1.FlowBatch {
	t.Helper()
	out := make([]*ebpfv1.FlowBatch, 0, len(values))
	for i, v := range values {
		var b ebpfv1.FlowBatch
		if err := proto.Unmarshal(v, &b); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		out = append(out, &b)
	}
	return out
}

// DPR-071: on the lab the cumulative service map grew one record past Kafka's
// 1,000,012-byte limit within four minutes; every later flush was rejected
// asynchronously while the agent logged "emitted". A flush above the bound now
// leaves as several records that together carry exactly the flush, each under
// the bound, keyed identically (same partition), and never as an edges-only
// record the topology view would reject (TENANT-006).
func TestBusEmitterSplitsAFlushThatExceedsTheRecordBound(t *testing.T) {
	const bound = 16 * 1024
	rb := &recordingBus{}
	em := NewBusEmitter(rb, "t1").WithMaxBatchBytes(bound)
	flows, edges, l7calls := syntheticFlush(300, 2000, 20)
	if err := em.Emit(context.Background(), flows, edges, l7calls); err != nil {
		t.Fatal(err)
	}
	if len(rb.values) < 3 {
		t.Fatalf("published %d records; a %d-edge flush must be split under a %d-byte bound", len(rb.values), len(edges), bound)
	}
	wantKey := string(bus.TenantKey("t1", "agent-1"))
	var gotFlows, gotEdges, gotL7 int
	seenEdges := map[string]int{}
	for i, v := range rb.values {
		if len(v) > bound {
			t.Errorf("record %d is %d bytes, above the %d-byte bound", i, len(v), bound)
		}
		if string(rb.keys[i]) != wantKey {
			t.Errorf("record %d key = %q, want %q (every record of a flush shares the partition key)", i, rb.keys[i], wantKey)
		}
	}
	for i, b := range decodeRecords(t, rb.values) {
		gotFlows += len(b.Flows)
		gotEdges += len(b.Edges)
		gotL7 += len(b.L7Calls)
		if len(b.Edges) > 0 && len(b.Flows) == 0 {
			t.Errorf("record %d carries %d edges and no flow: an edges-only record cannot be tenant-verified (TENANT-006)", i, len(b.Edges))
		}
		for _, e := range b.Edges {
			seenEdges[e.GetSource()+"|"+e.GetDestination()]++
		}
	}
	if gotFlows != len(flows) || gotEdges != len(edges) || gotL7 != len(l7calls) {
		t.Errorf("records carry flows=%d edges=%d l7=%d, want %d/%d/%d (nothing lost, nothing duplicated)",
			gotFlows, gotEdges, gotL7, len(flows), len(edges), len(l7calls))
	}
	for k, n := range seenEdges {
		if n != 1 {
			t.Errorf("edge %s appears %d times", k, n)
		}
	}
}

func TestBusEmitterKeepsOneRecordWhenTheFlushFits(t *testing.T) {
	rb := &recordingBus{}
	flows, edges, l7calls := syntheticFlush(10, 10, 2)
	if err := NewBusEmitter(rb, "t1").Emit(context.Background(), flows, edges, l7calls); err != nil {
		t.Fatal(err)
	}
	if len(rb.values) != 1 {
		t.Fatalf("published %d records, want 1 under the default %d-byte bound", len(rb.values), DefaultMaxBatchBytes)
	}
	b := decodeRecords(t, rb.values)[0]
	if len(b.Flows) != 10 || len(b.Edges) != 10 || len(b.L7Calls) != 2 {
		t.Errorf("record carries flows=%d edges=%d l7=%d", len(b.Flows), len(b.Edges), len(b.L7Calls))
	}
}

func TestBusEmitterUnboundedWhenTheLimitIsZero(t *testing.T) {
	rb := &recordingBus{}
	flows, edges, l7calls := syntheticFlush(50, 2000, 0)
	if err := NewBusEmitter(rb, "t1").WithMaxBatchBytes(0).Emit(context.Background(), flows, edges, l7calls); err != nil {
		t.Fatal(err)
	}
	if len(rb.values) != 1 {
		t.Fatalf("published %d records, want 1 (0 = unbounded)", len(rb.values))
	}
}

func TestChunkFlowBatchesDealsFlowsAcrossEveryEdgeRecord(t *testing.T) {
	flows, edges, _ := syntheticFlush(40, 600, 0)
	pf := make([]*ebpfv1.Flow, 0, len(flows))
	for i := range flows {
		pf = append(pf, flows[i].toProto())
	}
	pe := make([]*ebpfv1.ServiceEdge, 0, len(edges))
	for i := range edges {
		pe = append(pe, edges[i].toProto())
	}
	chunks := chunkFlowBatches(pf, pe, nil, 4096, "0.6.1-test")
	if len(chunks) < 4 {
		t.Fatalf("got %d chunks, want several under a 4 KiB bound", len(chunks))
	}
	for i, c := range chunks {
		if len(c.Edges) > 0 && len(c.Flows) == 0 {
			t.Errorf("chunk %d has edges but no flow", i)
		}
		if n := proto.Size(c); n > 4096 {
			t.Errorf("chunk %d encodes to %d bytes > 4096", i, n)
		}
	}
	// A limit smaller than a single element still yields one element per
	// record rather than an infinite loop or a dropped element.
	tiny := chunkFlowBatches(pf[:3], pe[:3], nil, 8, "0.6.1-test")
	var n int
	for _, c := range tiny {
		n += len(c.Flows) + len(c.Edges)
	}
	if n != 6 {
		t.Errorf("tiny limit lost elements: carried %d of 6", n)
	}
}
