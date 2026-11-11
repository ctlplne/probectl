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
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/version"
)

// EmitCounters publishes the original exact samples on their own tenant lane.
// This is delivery, not source attestation or durable-store acceptance. The
// receiver must independently bind the enrolled sender and original source.
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
	return e.bus.Publish(ctx, topic, bus.TenantKey(e.tenant, agent), value)
}
