package ebpf

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
)

// Emitter publishes a batch of observed flows + the current service edges. The
// agent emits OTel-shaped records; BusEmitter marshals them to protobuf and
// publishes to probectl.ebpf.flows, but the seam lets a future OTLP exporter (S22)
// drop in without touching the runtime.
type Emitter interface {
	Emit(ctx context.Context, flows []Flow, edges []ServiceEdge, l7 []L7Record) error
}

// BusEmitter publishes FlowBatches to the bus, tenant-keyed (pooled tagging).
type BusEmitter struct {
	bus    bus.Bus
	tenant string
	topic  string // shared, or the tenant's namespaced lane (TENANT-107)
}

// NewBusEmitter returns an Emitter that publishes to probectl.ebpf.flows.
func NewBusEmitter(b bus.Bus, tenant string) *BusEmitter {
	e, _ := NewNamespacedBusEmitter(b, tenant, "")
	return e
}

// NewNamespacedBusEmitter publishes to the tenant's namespaced lane when
// namespace is set (TENANT-107). A malformed namespace refuses construction
// (RED-006: never a silent shared-lane fallback).
func NewNamespacedBusEmitter(b bus.Bus, tenant, namespace string) (*BusEmitter, error) {
	topic, err := bus.TopicFor(namespace, bus.EBPFFlowsTopic)
	if err != nil {
		return nil, fmt.Errorf("ebpf: refusing to start: %w", err)
	}
	return &BusEmitter{bus: b, tenant: tenant, topic: topic}, nil
}

// Emit marshals the batch and publishes it. An empty batch is a no-op.
func (e *BusEmitter) Emit(ctx context.Context, flows []Flow, edges []ServiceEdge, l7calls []L7Record) error {
	if len(flows) == 0 && len(edges) == 0 && len(l7calls) == 0 {
		return nil
	}
	batch := &ebpfv1.FlowBatch{
		Flows:   make([]*ebpfv1.Flow, 0, len(flows)),
		Edges:   make([]*ebpfv1.ServiceEdge, 0, len(edges)),
		L7Calls: make([]*ebpfv1.L7Call, 0, len(l7calls)),
	}
	for i := range flows {
		batch.Flows = append(batch.Flows, flows[i].toProto())
	}
	for i := range edges {
		batch.Edges = append(batch.Edges, edges[i].toProto())
	}
	for i := range l7calls {
		batch.L7Calls = append(batch.L7Calls, l7calls[i].toProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("ebpf: marshal flow batch: %w", err)
	}
	return e.bus.Publish(ctx, e.topic, []byte(e.tenant), value)
}

func (f Flow) toProto() *ebpfv1.Flow {
	return &ebpfv1.Flow{
		TenantId:           f.TenantID,
		AgentId:            f.AgentID,
		Host:               f.Host,
		ObservedAtUnixNano: unixNano(f.Observed),
		SourceAddress:      f.Source.Address,
		SourcePort:         f.Source.Port,
		DestinationAddress: f.Destination.Address,
		DestinationPort:    f.Destination.Port,
		NetworkTransport:   f.Transport,
		NetworkType:        f.NetworkType,
		Pid:                f.Source.PID,
		ProcessName:        f.Source.Process,
		ContainerId:        f.Source.Container,
		Workload:           f.Source.Workload,
		Bytes:              f.Bytes,
		Packets:            f.Packets,
		Direction:          f.Direction,
		State:              f.State,
	}
}

func (e ServiceEdge) toProto() *ebpfv1.ServiceEdge {
	return &ebpfv1.ServiceEdge{
		TenantId:          e.TenantID,
		Source:            e.Source,
		Destination:       e.Destination,
		DestinationPort:   e.DestPort,
		NetworkTransport:  e.Transport,
		Connections:       e.Connections,
		Bytes:             e.Bytes,
		Packets:           e.Packets,
		FirstSeenUnixNano: unixNano(e.FirstSeen),
		LastSeenUnixNano:  unixNano(e.LastSeen),
		L7Protocol:        e.L7Protocol,
		L7Calls:           e.L7Calls,
		L7Errors:          e.L7Errors,
		L7LatencySumNano:  e.L7LatencySum.Nanoseconds(),
		L7LatencyMaxNano:  e.L7LatencyMax.Nanoseconds(),
	}
}

// L7Record is one parsed L7 call plus the connection/edge context the agent
// stamps it with (the client→server orientation), ready to emit and roll up.
type L7Record struct {
	TenantID    string
	AgentID     string
	Source      Endpoint
	Destination Endpoint
	Transport   string
	Encrypted   bool
	Call        l7.Call
}

func (r L7Record) toProto() *ebpfv1.L7Call {
	return &ebpfv1.L7Call{
		TenantId:        r.TenantID,
		AgentId:         r.AgentID,
		Source:          r.Source.ID(),
		Destination:     r.Destination.ID(),
		DestinationPort: r.Destination.Port,
		Protocol:        r.Call.Protocol,
		Method:          r.Call.Method,
		Resource:        r.Call.Resource,
		Status:          r.Call.Status,
		Error:           r.Call.Error,
		Encrypted:       r.Encrypted,
		StartUnixNano:   unixNano(r.Call.Start),
		LatencyNano:     r.Call.Latency.Nanoseconds(),
		RequestBytes:    r.Call.ReqBytes,
		ResponseBytes:   r.Call.RespBytes,
	}
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
