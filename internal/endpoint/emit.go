package endpoint

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/canary"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// Emitter publishes a sample's DEM results. The seam lets a test capture results
// and lets a future transport (the mTLS agent gRPC stream, for roaming devices)
// drop in without touching the runtime.
type Emitter interface {
	Emit(ctx context.Context, s Sample) error
}

// BusEmitter maps a Sample to canonical canary Results and publishes each to
// probectl.endpoint.results, tenant-keyed (pooled tenant-tagging), exactly like
// every other agent's results land on the bus.
type BusEmitter struct {
	bus    bus.Bus
	tenant string
	agent  string
	topic  string // shared, or the tenant's namespaced lane (TENANT-107)
}

// NewBusEmitter returns an Emitter publishing to probectl.endpoint.results.
func NewBusEmitter(b bus.Bus, tenant, agent string) *BusEmitter {
	e, _ := NewNamespacedBusEmitter(b, tenant, agent, "")
	return e
}

// NewNamespacedBusEmitter publishes to the tenant's namespaced lane when
// namespace is set (TENANT-107). A malformed namespace refuses construction
// (RED-006: never a silent shared-lane fallback).
func NewNamespacedBusEmitter(b bus.Bus, tenant, agent, namespace string) (*BusEmitter, error) {
	topic, err := bus.TopicFor(namespace, bus.EndpointResultsTopic)
	if err != nil {
		return nil, fmt.Errorf("endpoint: refusing to start: %w", err)
	}
	return &BusEmitter{bus: b, tenant: tenant, agent: agent, topic: topic}, nil
}

// Emit publishes one message per DEM result in the sample.
func (e *BusEmitter) Emit(ctx context.Context, s Sample) error {
	for _, r := range s.ToResults() {
		value, err := proto.Marshal(e.toProto(r))
		if err != nil {
			return fmt.Errorf("endpoint: marshal result: %w", err)
		}
		if err := e.bus.Publish(ctx, e.topic, bus.TenantKey(e.tenant, e.agent), value); err != nil {
			return err
		}
	}
	return nil
}

// toProto maps a canary.Result onto the canonical result schema, stamping the
// agent's tenant + id (the same mapping the canary agent uses).
func (e *BusEmitter) toProto(r canary.Result) *resultv1.Result {
	return &resultv1.Result{
		TenantId:          e.tenant,
		AgentId:           e.agent,
		CanaryType:        r.Type,
		ServerAddress:     r.Target,
		Success:           r.Success,
		ErrorMessage:      r.Error,
		StartTimeUnixNano: unixNano(r.StartedAt),
		DurationNano:      int64(r.Duration),
		Metrics:           r.Metrics,
		Attributes:        r.Attributes,
	}
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
