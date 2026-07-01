// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// FuzzTopologyChangeEventIngest hardens the graph-ingest side of the topology
// view. BGP, device telemetry, and eBPF service-edge protobuf payloads are
// untrusted bus frames; malformed bytes must be counted/skipped, not panic, and
// namespaced-lane ingestion must never mutate the tenant named inside the
// payload when the lane says otherwise.
func FuzzTopologyChangeEventIngest(f *testing.F) {
	now := time.Unix(1_750_000_000, 0)
	f.Add(byte(0), fuzzMarshal(f, &bgpv1.BGPEvent{
		TenantId:           fuzzOtherTenant,
		EventType:          bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE,
		Prefix:             "203.0.113.0/24",
		NewOriginAsn:       64500,
		PeerAsn:            64496,
		DetectedAtUnixNano: now.UnixNano(),
	}))
	f.Add(byte(1), fuzzMarshal(f, &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
		TenantId:      fuzzOtherTenant,
		AgentId:       "agent-device",
		DeviceAddress: "10.0.0.1",
		DeviceName:    "edge-r1",
		Source:        "snmp",
		Name:          "probectl.device.cpu.utilization",
		Value:         42,
		Unit:          "percent",
		TimeUnixNano:  now.UnixNano(),
		IfIndex:       1,
		IfName:        "eth0",
	}}}))
	f.Add(byte(2), fuzzMarshal(f, &ebpfv1.FlowBatch{
		Flows: []*ebpfv1.Flow{{
			TenantId:           fuzzOtherTenant,
			AgentId:            "agent-ebpf",
			Host:               "host-a",
			ObservedAtUnixNano: now.UnixNano(),
			SourceAddress:      "10.0.0.10",
			SourcePort:         49152,
			DestinationAddress: "10.0.0.20",
			DestinationPort:    8443,
			NetworkTransport:   "tcp",
			NetworkType:        "ipv4",
			Bytes:              4096,
			Packets:            16,
		}},
		Edges: []*ebpfv1.ServiceEdge{{
			TenantId:          fuzzOtherTenant,
			Source:            "checkout",
			Destination:       "payments",
			DestinationPort:   8443,
			NetworkTransport:  "tcp",
			Connections:       4,
			Bytes:             4096,
			Packets:           16,
			FirstSeenUnixNano: now.UnixNano(),
			LastSeenUnixNano:  now.Add(time.Second).UnixNano(),
			L7Protocol:        "grpc",
			L7Calls:           4,
		}},
	}))
	f.Add(byte(0), []byte("{ not protobuf"))
	f.Add(byte(2), []byte{})

	f.Fuzz(func(t *testing.T, plane byte, payload []byte) {
		if len(payload) > 1<<16 {
			t.Skip("bounded seed corpus: payload too large for unit-mode fuzz smoke")
		}
		st := topology.NewMemoryStore()
		tc := NewTopologyConsumer(nil, st, fuzzLogger())
		tc.clock = func() time.Time { return now }
		msg := bus.Message{Value: payload}
		var err error
		switch plane % 3 {
		case 0:
			err = tc.handleBGPLane(context.Background(), msg, fuzzTenant)
		case 1:
			err = tc.handleDeviceLane(context.Background(), msg, fuzzTenant)
		default:
			err = tc.handleEBPFLane(context.Background(), msg, fuzzTenant)
		}
		if err != nil {
			t.Fatalf("topology handler returned error: %v", err)
		}
		other := st.Latest(fuzzOtherTenant)
		if len(other.Nodes) != 0 || len(other.Edges) != 0 {
			t.Fatalf("payload-claimed tenant graph mutated despite lane tenant: nodes=%d edges=%d", len(other.Nodes), len(other.Edges))
		}
	})
}
