package ebpf

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/netctl/internal/bus"
	ebpfv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/ebpf/v1"
)

// Emitter publishes a batch of observed flows + the current service edges. The
// agent emits OTel-shaped records; BusEmitter marshals them to protobuf and
// publishes to netctl.ebpf.flows, but the seam lets a future OTLP exporter (S22)
// drop in without touching the runtime.
type Emitter interface {
	Emit(ctx context.Context, flows []Flow, edges []ServiceEdge) error
}

// BusEmitter publishes FlowBatches to the bus, tenant-keyed (pooled tagging).
type BusEmitter struct {
	bus    bus.Bus
	tenant string
}

// NewBusEmitter returns an Emitter that publishes to netctl.ebpf.flows.
func NewBusEmitter(b bus.Bus, tenant string) *BusEmitter {
	return &BusEmitter{bus: b, tenant: tenant}
}

// Emit marshals the batch and publishes it. An empty batch is a no-op.
func (e *BusEmitter) Emit(ctx context.Context, flows []Flow, edges []ServiceEdge) error {
	if len(flows) == 0 && len(edges) == 0 {
		return nil
	}
	batch := &ebpfv1.FlowBatch{
		Flows: make([]*ebpfv1.Flow, 0, len(flows)),
		Edges: make([]*ebpfv1.ServiceEdge, 0, len(edges)),
	}
	for i := range flows {
		batch.Flows = append(batch.Flows, flows[i].toProto())
	}
	for i := range edges {
		batch.Edges = append(batch.Edges, edges[i].toProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("ebpf: marshal flow batch: %w", err)
	}
	return e.bus.Publish(ctx, bus.EBPFFlowsTopic, []byte(e.tenant), value)
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
	}
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
