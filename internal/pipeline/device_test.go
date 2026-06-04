package pipeline

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// TestDeviceConsumerEndToEnd: a published DeviceMetricBatch lands in the TSDB
// with the prefixed metric name and bounded labels.
func TestDeviceConsumerEndToEnd(t *testing.T) {
	b := bus.NewMemory()
	w := tsdb.NewMemory()
	c := NewDeviceConsumer(b, w, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)

	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	batch := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
		TenantId: "t-a", AgentId: "a1", DeviceAddress: "192.0.2.1", DeviceName: "core-sw1",
		Source: "snmp", IfIndex: 1, IfName: "eth0",
		Name: "probectl.device.if.in.octets", Value: 1000, Unit: "octets",
		TimeUnixNano: at.UnixNano(),
	}}}
	value, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, bus.DeviceMetricsTopic, []byte("t-a"), value); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		series := w.Query("probectl_device_if_in_octets", nil)
		if len(series) >= 1 {
			s := series[0]
			if s.Metric != "probectl_device_if_in_octets" {
				t.Fatalf("metric = %q", s.Metric)
			}
			if s.Labels["tenant_id"] != "t-a" || s.Labels["device"] != "192.0.2.1" ||
				s.Labels["if_name"] != "eth0" || s.Labels["source"] != "snmp" || s.Labels["if_index"] != "1" {
				t.Fatalf("labels = %+v", s.Labels)
			}
			if s.Value != 1000 || s.TimeMillis != at.UnixMilli() {
				t.Fatalf("sample = %+v", s)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("series never landed")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Malformed payloads are dropped without wedging the consumer.
	_ = b.Publish(ctx, bus.DeviceMetricsTopic, []byte("t-a"), []byte("garbage"))
	time.Sleep(20 * time.Millisecond)
	if n := w.Len(); n != 1 {
		t.Fatalf("garbage changed the store: %d series", n)
	}
}
