package flow

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
)

// BusEmitter publishes FlowBatches to probectl.flow.events, tenant-keyed
// (pooled tenant-tagging, CLAUDE.md §6), mirroring the eBPF/endpoint emitters.
type BusEmitter struct {
	bus    bus.Bus
	tenant string
	topic  string // shared, or the tenant's namespaced lane (TENANT-107)
}

// NewBusEmitter returns an Emitter publishing to bus.FlowEventsTopic, or to
// the tenant's namespaced lane when namespace is set (siloed/hybrid tenants,
// TENANT-107). A malformed namespace is a CONSTRUCTION error — the agent
// refuses to start rather than silently publishing on the shared lane
// (RED-006, fail closed).
func NewBusEmitter(b bus.Bus, tenant string) *BusEmitter {
	e, _ := NewNamespacedBusEmitter(b, tenant, "")
	return e
}

// NewNamespacedBusEmitter is NewBusEmitter with an optional silo namespace.
func NewNamespacedBusEmitter(b bus.Bus, tenant, namespace string) (*BusEmitter, error) {
	topic, err := bus.TopicFor(namespace, bus.FlowEventsTopic)
	if err != nil {
		return nil, fmt.Errorf("flow: refusing to start: %w", err)
	}
	return &BusEmitter{bus: b, tenant: tenant, topic: topic}, nil
}

// Emit marshals the batch and publishes it. An empty batch is a no-op.
func (e *BusEmitter) Emit(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	batch := &flowv1.FlowBatch{Flows: make([]*flowv1.FlowRecord, 0, len(recs))}
	for i := range recs {
		batch.Flows = append(batch.Flows, recs[i].ToProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("flow: marshal batch: %w", err)
	}
	return e.bus.Publish(ctx, e.topic, []byte(e.tenant), value)
}
