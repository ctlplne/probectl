package device

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
)

// Emitter receives normalized metric batches (the bus emitter in production,
// a capture in tests).
type Emitter interface {
	Emit(ctx context.Context, ms []Metric) error
}

// BusEmitter publishes DeviceMetricBatches to probectl.device.metrics,
// tenant-keyed (pooled tenant-tagging, CLAUDE.md §6).
type BusEmitter struct {
	bus    bus.Bus
	tenant string
}

// NewBusEmitter returns an Emitter publishing to bus.DeviceMetricsTopic.
func NewBusEmitter(b bus.Bus, tenant string) *BusEmitter {
	return &BusEmitter{bus: b, tenant: tenant}
}

// Emit marshals the batch and publishes it. An empty batch is a no-op.
func (e *BusEmitter) Emit(ctx context.Context, ms []Metric) error {
	if len(ms) == 0 {
		return nil
	}
	batch := &devicev1.DeviceMetricBatch{Metrics: make([]*devicev1.DeviceMetric, 0, len(ms))}
	for i := range ms {
		batch.Metrics = append(batch.Metrics, ms[i].ToProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("device: marshal batch: %w", err)
	}
	return e.bus.Publish(ctx, bus.DeviceMetricsTopic, []byte(e.tenant), value)
}
