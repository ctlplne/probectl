// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/device"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func TestTopologyConsumerPhysicalSnapshotReplaceNativeAPITenantScoped(t *testing.T) {
	topologyStore := topology.NewMemoryStore()
	neighborStore := device.NewMemoryNeighborStore()
	consumer := NewTopologyConsumer(nil, topologyStore, intelTestLog()).
		WithDeviceNeighborStore(neighborStore)
	receivedAt := time.Now().UTC().Truncate(time.Second)
	consumer.clock = func() time.Time { return receivedAt }
	tenantA := tenancy.DefaultTenantID.String()
	tenantB := "00000000-0000-0000-0000-000000000002"
	eventAt := receivedAt.Add(-5 * time.Minute)

	emit := func(
		tenant, agent, address, name string,
		at time.Time,
		neighbors ...*devicev1.DeviceNeighborEvidence,
	) {
		t.Helper()
		payload, err := proto.Marshal(&devicev1.DeviceNeighborSnapshot{
			TenantId: tenant, AgentId: agent, DeviceAddress: address, DeviceName: name,
			ObservedAtUnixNano: at.UnixNano(), Neighbors: neighbors,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := consumer.handleDeviceNeighbors(
			context.Background(),
			bus.Message{Key: []byte(tenant), Value: payload},
		); err != nil {
			t.Fatal(err)
		}
	}
	neighbor := func(tenant, agent, chassis, name, localPort string, at time.Time) *devicev1.DeviceNeighborEvidence {
		return &devicev1.DeviceNeighborEvidence{
			TenantId: tenant, AgentId: agent, LocalPortId: localPort,
			RemoteChassisId: chassis, RemoteDeviceName: name, RemotePortId: "Ethernet1",
			Protocol: "lldp", Confidence: 0.95, ObservedAtUnixNano: at.UnixNano(),
			FreshUntilUnixNano: at.Add(10 * time.Minute).UnixNano(),
		}
	}

	emit(tenantA, "agent-a", "10.0.0.1", "core-a", eventAt,
		neighbor(tenantA, "agent-a", "leaf-a", "leaf-a", "Gi0/1", eventAt))
	emit(tenantA, "agent-b", "10.0.0.2", "core-b", eventAt,
		neighbor(tenantA, "agent-b", "leaf-b", "leaf-b", "Gi0/2", eventAt))
	emit(tenantB, "agent-a", "10.0.0.9", "secret-core", eventAt,
		neighbor(tenantB, "agent-a", "secret-leaf", "secret-leaf", "Gi0/9", eventAt))
	emit(tenantA, "agent-a", "10.0.0.1", "core-a", eventAt.Add(time.Minute))

	rows, _, err := neighborStore.ListNeighbors(context.Background(), tenantA, device.NeighborFilter{})
	if err != nil || len(rows) != 1 || rows[0].AgentID != "agent-b" {
		t.Fatalf("current device evidence = %+v err=%v", rows, err)
	}
	current := topologyStore.Latest(tenantA)
	if coverage := topology.SnapshotCoverage(current); coverage.PhysicalEdges != len(rows) {
		t.Fatalf("topology/device evidence diverged: coverage=%+v rows=%+v", coverage, rows)
	}
	if foreign := topologyStore.Latest(tenantB); topology.SnapshotCoverage(foreign).PhysicalEdges != 1 {
		t.Fatalf("tenant-a replacement touched tenant-b: %+v", foreign.Edges)
	}
	if historical := topologyStore.SnapshotAt(tenantA, eventAt); topology.SnapshotCoverage(historical).PhysicalEdges != 2 {
		t.Fatalf("replacement destroyed event-time topology: %+v", historical.Edges)
	}

	server := testServer(fakePinger{}).WithTopology(topologyStore)
	response := do(server, http.MethodGet, "/v1/topology")
	if response.Code != http.StatusOK {
		t.Fatalf("topology API status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Edges    []topology.VizEdge `json:"edges"`
		Coverage topology.Coverage  `json:"coverage"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Coverage.PhysicalEdges != 1 || len(body.Edges) != 1 ||
		body.Edges[0].Kind != string(topology.EdgePhysical) ||
		strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("native topology API leaked or contradicted evidence: %+v body=%s",
			body, response.Body.String())
	}
}
