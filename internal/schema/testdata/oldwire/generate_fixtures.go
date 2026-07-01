//go:build ignore

// Regenerate the committed old-wire fixtures in this directory.
//
// These bytes model older deployed agents/bridges that only populated the
// fields below. The compatibility test must keep decoding the committed bytes
// with current generated code; do not regenerate casually.
package main

import (
	"log"
	"os"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

func main() {
	write("result_v1_result.pb", &resultv1.Result{
		TenantId:            "tenant-old",
		AgentId:             "agent-old",
		CanaryType:          "http",
		ServerAddress:       "example.internal",
		ServerPort:          443,
		NetworkTransport:    "tcp",
		NetworkProtocolName: "http",
		Success:             true,
		StartTimeUnixNano:   1700000000000000000,
		DurationNano:        42000000,
		Metrics:             map[string]float64{"rtt.avg.ms": 42},
		Attributes:          map[string]string{"http.method": "GET"},
	})
	write("bgp_v1_event.pb", &bgpv1.BGPEvent{
		TenantId:           "tenant-old",
		EventType:          bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE,
		Severity:           bgpv1.Severity_SEVERITY_WARNING,
		Confidence:         0.82,
		Prefix:             "203.0.113.0/24",
		NewOriginAsn:       64512,
		OldOriginAsn:       64500,
		NewAsPath:          []uint32{64496, 64512},
		OldAsPath:          []uint32{64496, 64500},
		ExpectedOrigins:    []uint32{64500},
		RpkiStatus:         bgpv1.RpkiStatus_RPKI_STATUS_NOT_FOUND,
		Collector:          "rrc00",
		PeerAsn:            64496,
		PeerAddress:        "192.0.2.10",
		Message:            "origin changed",
		DetectedAtUnixNano: 1700000001000000000,
	})
	write("flow_v1_batch.pb", &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId:           "tenant-old",
		AgentId:            "flow-agent-old",
		ExporterAddress:    "198.51.100.10",
		ObservationDomain:  7,
		FlowProtocol:       "ipfix",
		ObservedAtUnixNano: 1700000002000000000,
		StartUnixNano:      1700000001000000000,
		EndUnixNano:        1700000002000000000,
		SourceAddress:      "10.0.0.10",
		SourcePort:         53000,
		DestinationAddress: "10.0.1.20",
		DestinationPort:    443,
		NetworkTransport:   "tcp",
		NetworkType:        "ipv4",
		InputInterface:     11,
		OutputInterface:    12,
		Bytes:              123456,
		Packets:            789,
	}}})
	write("device_v1_batch.pb", &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
		TenantId:      "tenant-old",
		AgentId:       "device-agent-old",
		DeviceAddress: "192.0.2.20",
		DeviceName:    "core-sw-old",
		Source:        "snmp",
		IfIndex:       3,
		IfName:        "xe-0/0/0",
		Name:          "probectl.device.if.in.octets",
		Value:         1234,
		Unit:          "octets",
		TimeUnixNano:  1700000003000000000,
	}}})
	write("ebpf_v1_batch.pb", &ebpfv1.FlowBatch{
		Flows: []*ebpfv1.Flow{{
			TenantId:           "tenant-old",
			AgentId:            "ebpf-agent-old",
			Host:               "node-old",
			ObservedAtUnixNano: 1700000004000000000,
			SourceAddress:      "10.2.0.4",
			SourcePort:         41000,
			DestinationAddress: "10.2.1.8",
			DestinationPort:    5432,
			NetworkTransport:   "tcp",
			NetworkType:        "ipv4",
			Pid:                4242,
			ProcessName:        "payments",
			Workload:           "payments-api",
			Bytes:              4096,
			Packets:            32,
			Direction:          "egress",
			State:              "established",
		}},
		Edges: []*ebpfv1.ServiceEdge{{
			TenantId:          "tenant-old",
			Source:            "payments-api",
			Destination:       "postgres",
			DestinationPort:   5432,
			NetworkTransport:  "tcp",
			Connections:       2,
			Bytes:             4096,
			Packets:           32,
			FirstSeenUnixNano: 1700000004000000000,
			LastSeenUnixNano:  1700000005000000000,
		}},
	})
	write("agent_v1_register_response.pb", &agentv1.RegisterResponse{
		AgentId:                  "agent-old",
		TenantId:                 "tenant-old",
		ConfigEpoch:              41,
		HeartbeatIntervalSeconds: 30,
	})
}

func write(name string, m proto.Message) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		log.Fatalf("marshal %s: %v", name, err)
	}
	if err := os.WriteFile(name, b, 0o644); err != nil {
		log.Fatalf("write %s: %v", name, err)
	}
}
