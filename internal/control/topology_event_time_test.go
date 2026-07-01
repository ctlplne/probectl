// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

func TestTopologyConsumerUsesEventTimeForBGP(t *testing.T) {
	store := topology.NewMemoryStore()
	tc := NewTopologyConsumer(nil, store, intelTestLog())
	receivedAt := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	eventAt := receivedAt.Add(-2 * time.Hour)
	tc.clock = func() time.Time { return receivedAt }

	raw, err := proto.Marshal(&bgpv1.BGPEvent{
		TenantId:           "t1",
		Prefix:             "198.51.100.0/24",
		NewOriginAsn:       64500,
		DetectedAtUnixNano: eventAt.UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.handleBGP(context.Background(), bus.Message{Key: []byte("t1"), Value: raw}); err != nil {
		t.Fatal(err)
	}

	if snap := store.SnapshotAt("t1", eventAt); len(snap.Edges) == 0 {
		t.Fatalf("BGP event-time snapshot has no routing edge: %+v", snap)
	}
	if snap := store.SnapshotAt("t1", receivedAt); len(snap.Edges) != 0 {
		t.Fatalf("BGP was stamped at receive time instead of event time: %+v", snap.Edges)
	}
}

func TestTopologyConsumerUsesEventWindowForEBPF(t *testing.T) {
	store := topology.NewMemoryStore()
	tc := NewTopologyConsumer(nil, store, intelTestLog())
	receivedAt := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	firstSeen := receivedAt.Add(-2 * time.Hour)
	lastSeen := firstSeen.Add(10 * time.Minute)
	tc.clock = func() time.Time { return receivedAt }

	raw, err := proto.Marshal(&ebpfv1.FlowBatch{Edges: []*ebpfv1.ServiceEdge{{
		TenantId:          "t1",
		Source:            "checkout",
		Destination:       "orders",
		DestinationPort:   8443,
		FirstSeenUnixNano: firstSeen.UnixNano(),
		LastSeenUnixNano:  lastSeen.UnixNano(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.handleEBPF(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}

	if snap := store.SnapshotAt("t1", firstSeen.Add(5*time.Minute)); len(snap.Edges) == 0 {
		t.Fatalf("eBPF event window snapshot has no service edge: %+v", snap)
	}
	if snap := store.SnapshotAt("t1", receivedAt); len(snap.Edges) != 0 {
		t.Fatalf("eBPF was stamped at receive time instead of event window: %+v", snap.Edges)
	}
}

func TestTopologyConsumerUsesEventTimeForDevice(t *testing.T) {
	store := topology.NewMemoryStore()
	tc := NewTopologyConsumer(nil, store, intelTestLog())
	receivedAt := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	eventAt := receivedAt.Add(-90 * time.Minute)
	tc.clock = func() time.Time { return receivedAt }

	raw, err := proto.Marshal(&devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
		TenantId:      "t1",
		DeviceAddress: "10.0.0.9",
		DeviceName:    "edge-r1",
		TimeUnixNano:  eventAt.UnixNano(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.handleDevice(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}

	if snap := store.SnapshotAt("t1", eventAt); len(snap.Nodes) == 0 {
		t.Fatalf("device event-time snapshot has no device node: %+v", snap)
	}
	if snap := store.SnapshotAt("t1", receivedAt); len(snap.Nodes) != 0 {
		t.Fatalf("device was stamped at receive time instead of event time: %+v", snap.Nodes)
	}
}
