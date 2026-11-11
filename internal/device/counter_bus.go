// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/entity"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/version"
)

// EmitCounters persists the complete authenticated witness before publishing
// original bytes on their tenant lane. The receiver must independently verify
// that witness and current source; this write receipt confers no reader grant.
func (e *BusEmitter) EmitCounters(ctx context.Context, metrics []Metric) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(metrics) == 0 {
		return nil
	}
	invalid := errors.New("device: complete exact counters require one bound tenant and sender")
	if e.tenant == "" || strings.TrimSpace(e.tenant) != e.tenant {
		return invalid
	}
	agent := metrics[0].AgentID
	if agent == "" || strings.TrimSpace(agent) != agent {
		return invalid
	}
	seen := make(map[struct {
		index uint32
		name  string
	}]struct{}, len(metrics))
	for _, metric := range metrics {
		if err := ctx.Err(); err != nil {
			return err
		}
		counter := metric.ExactCounter
		if metric.TenantID != e.tenant || metric.AgentID != agent || metric.Source != SourceSNMP || metric.Device == "" || metric.IfIndex == 0 || !isCounter(metric.Name) || counter == nil {
			return invalid
		}
		if (counter.Width != 32 && counter.Width != 64) || (counter.Width == 32 && counter.Value > 1<<32-1) || metric.At.IsZero() || !counter.PollStartedAt.Equal(metric.At) || counter.PollCompletedAt.Before(counter.PollStartedAt) {
			return invalid
		}
		if metric.Device != metrics[0].Device || !counter.PollStartedAt.Equal(metrics[0].ExactCounter.PollStartedAt) || !counter.PollCompletedAt.Equal(metrics[0].ExactCounter.PollCompletedAt) {
			return invalid
		}
		key := struct {
			index uint32
			name  string
		}{metric.IfIndex, metric.Name}
		if _, exists := seen[key]; exists {
			return invalid
		}
		seen[key] = struct{}{}
	}
	if e.counterWitness == nil {
		return ErrCounterWitnessUnavailable
	}
	topic, err := bus.TopicFor(e.namespace, bus.DeviceCountersTopic)
	if err != nil {
		return err
	}
	batch := &devicev1.DeviceMetricBatch{AgentVersion: version.Get().Version, Metrics: make([]*devicev1.DeviceMetric, 0, len(metrics))}
	for _, metric := range metrics {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch.Metrics = append(batch.Metrics, metric.ToProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return err
	}

	// Derive the witness from the actual owned wire bytes, rather than from
	// caller slices that might no longer describe the encoded population.
	parsed, err := ParseCounterBatch(ctx, e.tenant, value, e.counterMemoryBytes, e.counterWorkUnits)
	if err != nil {
		return err
	}
	digest, input := parsed.Digest, parsed.Input
	expected, err := entity.CounterCaptureKey(e.tenant, agent, digest, input)
	if err != nil {
		return invalid
	}
	captured, err := e.counterWitness.CaptureCounters(ctx, agent, digest, input)
	if err != nil {
		return err
	}
	if captured.Key != expected || captured.CapturedAt.UnixNano() <= 0 {
		return ErrCounterWitnessUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.bus.Publish(ctx, topic, bus.TenantKey(e.tenant, agent), value)
}

var ErrCounterWitnessUnavailable = errors.New("device: authenticated counter source witness required")

// CounterWitnessClient is implemented by the existing restricted evidence mTLS
// client. The bus never turns a claimed sender into a source grant.
type CounterWitnessClient interface {
	CaptureCounters(context.Context, string, [32]byte, entity.CounterCaptureInput) (entity.CounterCaptureReference, error)
}

// WithCounterWitness attaches the separately verified channel before runtime
// starts. Missing or refused evidence prevents raw publication; legacy metrics
// continue through their unchanged lane.
func (e *BusEmitter) WithCounterWitness(client CounterWitnessClient) *BusEmitter {
	e.counterWitness = client
	return e
}

// WithCounterResources sets whole-poll validation admission before runtime
// starts. Raising these operator resources never truncates a poll to fit.
func (e *BusEmitter) WithCounterResources(memoryBytes, workUnits int64) error {
	if memoryBytes <= 0 || workUnits <= 0 {
		return ErrCounterBatchInvalid
	}
	e.counterMemoryBytes, e.counterWorkUnits = memoryBytes, workUnits
	return nil
}
