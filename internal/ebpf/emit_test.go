package ebpf

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/netctl/internal/bus"
	ebpfv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/ebpf/v1"
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

	if err := em.Emit(context.Background(), flows, edges); err != nil {
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
}

func TestBusEmitterEmptyBatchIsNoop(t *testing.T) {
	fb := &fakeBus{}
	if err := NewBusEmitter(fb, "t1").Emit(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if fb.calls != 0 {
		t.Error("empty batch must not publish")
	}
}
