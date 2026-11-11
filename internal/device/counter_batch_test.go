// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

func counterBatchFixture(tenant string) *devicev1.DeviceMetricBatch {
	start := time.Unix(1794000000, 123456789)
	zero := uint32(0)
	metrics := make([]*devicev1.DeviceMetric, 0, 4)
	for _, name := range []string{MetricIfInOctets, MetricIfOutOctets} {
		for _, width := range []uint32{32, 64} {
			value := uint64(1<<32 - 1)
			if width == 64 {
				value = ^uint64(0)
			}
			metric := Metric{TenantID: tenant, AgentID: "same-agent", Device: "192.0.2.1", Source: SourceSNMP, IfIndex: uint32(width), Name: name, At: start,
				ExactCounter: &CounterValue{Value: value, Width: width, UptimeTicks: &zero, DiscontinuityTicks: &zero, PollStartedAt: start, PollCompletedAt: start.Add(123 * time.Nanosecond)}}
			metrics = append(metrics, metric.ToProto())
		}
	}
	return &devicev1.DeviceMetricBatch{Metrics: metrics, AgentVersion: "test"}
}

func TestRawCounterBatchKeepsWholeExactOriginalPollAndTenantDigest(t *testing.T) {
	var keys [2][32]byte
	for lane, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		batch := counterBatchFixture(tenant)
		raw, err := proto.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseCounterBatch(t.Context(), tenant, raw, 8<<20, 8<<20)
		if err != nil || got.Input.PointCount != 4 || got.Input.ConfiguredTarget != "192.0.2.1" || got.Sender != "same-agent" || !proto.Equal(batch, &devicev1.DeviceMetricBatch{Metrics: got.Metrics, AgentVersion: batch.AgentVersion}) {
			t.Fatal("original counter batch lost complete values, zero clock presence or scope", err)
		}
		var digest [32]byte
		copy(digest[:], crypto.Hash(raw))
		if got.Digest != digest || got.Input.PollStartedAt.UnixNano() != batch.Metrics[0].TimeUnixNano || got.Input.PollCompletedAt.UnixNano() != batch.Metrics[0].ExactCounter.PollCompletedAtUnixNano {
			t.Fatal("counter witness rounded clocks or hashed a reserialized subset")
		}
		keys[lane], err = entity.CounterCaptureKey(tenant, got.Sender, got.Digest, got.Input)
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 255
		batch.Metrics[0].ExactCounter.Value = 0
		if got.Metrics[0].ExactCounter.Value != 1<<32-1 {
			t.Fatal("parsed observations retained borrowed raw or producer memory")
		}
	}
	if keys[0] == keys[1] {
		t.Fatal("whole poll witness crossed tenants reusing all source identifiers")
	}
}

func TestRawCounterBatchRefusesForeignOrIncompleteWholePolls(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	for _, change := range []func(*devicev1.DeviceMetricBatch){
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].TenantId = "66666666-6666-4666-8666-666666666666" },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].AgentId = "spoofed" },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].DeviceAddress = "192.0.2.2" },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].ExactCounter.PollCompletedAtUnixNano++ },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].ExactCounter = nil },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[0].ExactCounter.Value = 1 << 32 },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].IfIndex = 0 },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].TimeUnixNano++ },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].Source = SourceGNMI },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].Name = MetricUptimeSeconds },
		func(b *devicev1.DeviceMetricBatch) {
			b.Metrics = append(b.Metrics, proto.Clone(b.Metrics[0]).(*devicev1.DeviceMetric))
		},
		func(b *devicev1.DeviceMetricBatch) { b.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
		func(b *devicev1.DeviceMetricBatch) { b.Metrics[3].ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
		func(b *devicev1.DeviceMetricBatch) {
			b.Metrics[3].ExactCounter.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
		},
	} {
		batch := counterBatchFixture(tenant)
		change(batch)
		raw, err := proto.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ParseCounterBatch(t.Context(), tenant, raw, 8<<20, 8<<20); err == nil || got.Metrics != nil || got.Digest != ([32]byte{}) {
			t.Fatal("invalid complete poll yielded a partial counter population or witness")
		}
	}
	raw, err := proto.Marshal(counterBatchFixture(tenant))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseCounterBatch(t.Context(), tenant, raw, 1, 1); err == nil || got.Metrics != nil {
		t.Fatal("counter decode ignored finite allocation/work admission")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := ParseCounterBatch(ctx, tenant, raw, 8<<20, 8<<20); !errors.Is(err, context.Canceled) || got.Metrics != nil {
		t.Fatal("canceled counter batch returned a population", err)
	}
}
