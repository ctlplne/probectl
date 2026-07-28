// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/device"
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

func TestTopologyConsumerPersistsAndFoldsPhysicalNeighborEvidence(t *testing.T) {
	topoStore := topology.NewMemoryStore()
	neighbors := device.NewMemoryNeighborStore()
	tc := NewTopologyConsumer(nil, topoStore, intelTestLog()).WithDeviceNeighborStore(neighbors)
	receivedAt := time.Now().UTC().Truncate(time.Second)
	eventAt := receivedAt.Add(-5 * time.Minute)
	tc.clock = func() time.Time { return receivedAt }
	raw, err := proto.Marshal(&devicev1.DeviceNeighborSnapshot{
		TenantId: "tenant-a", AgentId: "agent-a", DeviceAddress: "10.0.0.1",
		DeviceName: "core-a", ObservedAtUnixNano: eventAt.UnixNano(),
		Neighbors: []*devicev1.DeviceNeighborEvidence{{
			TenantId: "tenant-a", AgentId: "agent-a", LocalPortId: "xe-0/0/1",
			RemoteChassisId: "aa:bb:cc:dd:ee:ff", RemoteDeviceName: "leaf-a",
			RemotePortId: "Ethernet1", Protocol: "lldp", Confidence: 0.95,
			ObservedAtUnixNano: eventAt.UnixNano(),
			FreshUntilUnixNano: eventAt.Add(2 * time.Minute).UnixNano(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.handleDeviceNeighbors(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := neighbors.ListNeighbors(context.Background(), "tenant-a", device.NeighborFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("persisted rows=%+v err=%v", rows, err)
	}
	snap := topoStore.SnapshotAt("tenant-a", eventAt)
	if len(snap.Edges) != 1 || snap.Edges[0].Kind != topology.EdgePhysical ||
		snap.Edges[0].Label != "xe-0/0/1 ↔ Ethernet1" ||
		snap.Edges[0].Attributes["probectl.agent.id"] != "agent-a" ||
		snap.Edges[0].Attributes["probectl.device.neighbor.fresh_until"] != eventAt.Add(2*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("physical topology = %+v", snap)
	}
	if foreign := topoStore.Latest("tenant-b"); len(foreign.Nodes) != 0 || len(foreign.Edges) != 0 {
		t.Fatalf("neighbor evidence crossed tenant boundary: %+v", foreign)
	}
}

func TestTopologyConsumerStrictLaneRejectsSharedNeighborPersistence(t *testing.T) {
	topoStore := topology.NewMemoryStore()
	neighbors := device.NewMemoryNeighborStore()
	tc := NewTopologyConsumer(nil, topoStore, intelTestLog()).
		WithDeviceNeighborStore(neighbors).
		WithTenantBinding(allowTopologyBinding{}).
		WithStrictTenantLanes(true)
	now := time.Now().UTC()
	raw, err := proto.Marshal(&devicev1.DeviceNeighborSnapshot{
		TenantId: "tenant-a", AgentId: "agent-a", DeviceAddress: "10.0.0.1",
		ObservedAtUnixNano: now.UnixNano(),
		Neighbors: []*devicev1.DeviceNeighborEvidence{{
			TenantId: "tenant-a", AgentId: "agent-a", LocalPortId: "port-1",
			RemoteChassisId: "leaf-a", RemotePortId: "port-2", Protocol: "lldp",
			FreshUntilUnixNano: now.Add(time.Minute).UnixNano(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.handleDeviceNeighborLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatal(err)
	}
	rows, _, err := neighbors.ListNeighbors(context.Background(), "tenant-a", device.NeighborFilter{})
	if err != nil || len(rows) != 0 {
		t.Fatalf("shared strict lane persisted neighbors=%+v err=%v", rows, err)
	}
	if err := tc.handleDeviceNeighborLane(context.Background(), bus.Message{Value: raw}, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	rows, _, err = neighbors.ListNeighbors(context.Background(), "tenant-a", device.NeighborFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("tenant lane neighbors=%+v err=%v", rows, err)
	}
}

func TestTopologyConsumerPersistsTenantScopedCollectionOutcomes(t *testing.T) {
	topoStore := topology.NewMemoryStore()
	outcomes := device.NewMemoryCollectionOutcomeStore()
	tc := NewTopologyConsumer(nil, topoStore, intelTestLog()).
		WithDeviceCollectionOutcomeStore(outcomes)
	receivedAt := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	eventAt := receivedAt.Add(-5 * time.Minute)
	tc.clock = func() time.Time { return receivedAt }

	raw, err := proto.Marshal(&devicev1.DeviceCollectionOutcomeBatch{
		Outcomes: []*devicev1.DeviceCollectionOutcome{{
			TenantId: "payload-tenant", AgentId: "agent-a",
			ConfiguredTarget: "router-a.internal", Protocol: "lldp",
			LastAttemptAtUnixNano: eventAt.UnixNano(),
			State:                 device.CollectionStateFailed, Reason: device.CollectionReasonPollFailed,
			NextAction: device.CollectionActionVerifyLocalAccess,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.handleDeviceCollectionOutcomeLane(
		context.Background(), bus.Message{Value: raw}, "tenant-a",
	); err != nil {
		t.Fatal(err)
	}
	rows, _, err := outcomes.ListCollectionOutcomes(context.Background(), "tenant-a", device.CollectionOutcomeFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("tenant-a outcomes=%+v err=%v", rows, err)
	}
	if rows[0].TenantID != "tenant-a" || rows[0].ConfiguredTarget != "router-a.internal" ||
		rows[0].LastAttemptAt == nil || !rows[0].LastAttemptAt.Equal(eventAt) {
		t.Fatalf("normalized receipt=%+v", rows[0])
	}
	foreign, _, err := outcomes.ListCollectionOutcomes(context.Background(), "payload-tenant", device.CollectionOutcomeFilter{})
	if err != nil || len(foreign) != 0 {
		t.Fatalf("payload tenant received lane-stamped receipt=%+v err=%v", foreign, err)
	}
}

func TestTopologyConsumerRejectsMixedCollectionOutcomeBatchBeforeWrite(t *testing.T) {
	outcomes := device.NewMemoryCollectionOutcomeStore()
	tc := NewTopologyConsumer(nil, topology.NewMemoryStore(), intelTestLog()).
		WithDeviceCollectionOutcomeStore(outcomes)
	now := time.Now().UTC()
	raw, err := proto.Marshal(&devicev1.DeviceCollectionOutcomeBatch{
		Outcomes: []*devicev1.DeviceCollectionOutcome{
			{
				TenantId: "tenant-a", AgentId: "agent-a", ConfiguredTarget: "router-a",
				Protocol: "lldp", LastAttemptAtUnixNano: now.UnixNano(),
				State: device.CollectionStateHealthyEmpty, Reason: device.CollectionReasonNoRowsObserved,
				NextAction: device.CollectionActionReviewConfiguration,
			},
			{
				TenantId: "tenant-b", AgentId: "agent-b", ConfiguredTarget: "secret-router",
				Protocol: "cdp", LastAttemptAtUnixNano: now.UnixNano(),
				State: device.CollectionStateFailed, Reason: device.CollectionReasonPollFailed,
				NextAction: device.CollectionActionVerifyLocalAccess,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.handleDeviceCollectionOutcomes(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		rows, _, listErr := outcomes.ListCollectionOutcomes(context.Background(), tenant, device.CollectionOutcomeFilter{})
		if listErr != nil || len(rows) != 0 {
			t.Fatalf("%s received partial mixed batch=%+v err=%v", tenant, rows, listErr)
		}
	}
}
