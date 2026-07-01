// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

const (
	fuzzTenant      = "tenant-fuzz"
	fuzzOtherTenant = "seed-other"
)

type fuzzFataler interface {
	Helper()
	Fatalf(string, ...any)
}

func fuzzLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func fuzzMarshal(t fuzzFataler, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	return b
}

// FuzzNDRObservationDecode hardens the NDR consumer's bus-facing decode and
// classification path. The payload bytes are untrusted protobuf frames from
// DNS result, device-flow, and eBPF lanes. The invariants are ELI5-simple:
// arbitrary bytes must not panic, malformed frames are skipped, and any
// detection that survives decode/classification is scoped to the authoritative
// lane tenant rather than a payload-claimed tenant.
func FuzzNDRObservationDecode(f *testing.F) {
	now := time.Unix(1_750_000_000, 0).UnixNano()
	f.Add(byte(0), fuzzMarshal(f, &resultv1.Result{
		TenantId:          fuzzOtherTenant,
		AgentId:           "agent-a",
		CanaryType:        "dns",
		ServerAddress:     "aaaaaaaaaaaaaaaaaaaaaaaa.example",
		StartTimeUnixNano: now,
	}))
	f.Add(byte(1), fuzzMarshal(f, &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId:           fuzzOtherTenant,
		AgentId:            "agent-flow",
		ExporterAddress:    "192.0.2.1",
		ObservationDomain:  1,
		FlowProtocol:       "ipfix",
		ObservedAtUnixNano: now,
		EndUnixNano:        now,
		SourceAddress:      "10.0.0.10",
		SourcePort:         49152,
		DestinationAddress: "198.51.100.20",
		DestinationPort:    443,
		NetworkTransport:   "tcp",
		NetworkType:        "ipv4",
		InputInterface:     1,
		OutputInterface:    2,
		Bytes:              2048,
		Packets:            8,
		SamplingRate:       1,
		BytesScaled:        2048,
		PacketsScaled:      8,
		SourceAsn:          64501,
		SourceAsName:       "Example",
		SourceCountry:      "ZZ",
		DestinationAsn:     64500,
		DestinationAsName:  "Example",
		DestinationCountry: "ZZ",
	}}}))
	f.Add(byte(2), fuzzMarshal(f, &ebpfv1.FlowBatch{
		Flows: []*ebpfv1.Flow{{
			TenantId:           fuzzOtherTenant,
			AgentId:            "agent-ebpf",
			Host:               "host-a",
			ObservedAtUnixNano: now,
			SourceAddress:      "10.0.0.11",
			SourcePort:         53000,
			DestinationAddress: "203.0.113.9",
			DestinationPort:    53,
			NetworkTransport:   "udp",
			NetworkType:        "ipv4",
			Bytes:              512,
			Packets:            2,
			Direction:          "egress",
		}},
		L7Calls: []*ebpfv1.L7Call{{
			TenantId:        fuzzOtherTenant,
			AgentId:         "agent-ebpf",
			Source:          "workload-a",
			Destination:     "dns",
			DestinationPort: 53,
			Protocol:        "dns",
			Method:          "A",
			Resource:        "bbbbbbbbbbbbbbbb.example",
			Status:          "NOERROR",
			StartUnixNano:   now,
			LatencyNano:     int64(time.Millisecond),
		}},
	}))
	f.Add(byte(0), []byte("{ not protobuf"))
	f.Add(byte(1), []byte{})

	rules, err := threat.LoadRules("")
	if err != nil {
		f.Fatalf("load rules: %v", err)
	}

	f.Fuzz(func(t *testing.T, plane byte, payload []byte) {
		if len(payload) > 1<<16 {
			t.Skip("bounded seed corpus: payload too large for unit-mode fuzz smoke")
		}
		ds := threat.NewDetectionStore(64)
		cs := NewNDRConsumer(nil, threat.NewEngine(rules, nil, nil), nil, fuzzLogger()).WithDetections(ds)
		msg := bus.Message{Value: payload}
		var err error
		switch plane % 3 {
		case 0:
			err = cs.handleResultLane(context.Background(), msg, fuzzTenant)
		case 1:
			err = cs.handleFlowBatchLane(context.Background(), msg, fuzzTenant)
		default:
			err = cs.handleEBPFBatchLane(context.Background(), msg, fuzzTenant)
		}
		if err != nil {
			t.Fatalf("ndr handler returned error: %v", err)
		}
		if n := ds.Len(""); n != 0 {
			t.Fatalf("unscoped detections stored: %d", n)
		}
		if n := ds.Len(fuzzOtherTenant); n != 0 {
			t.Fatalf("payload-claimed tenant detections stored despite lane tenant: %d", n)
		}
		for _, d := range ds.List(fuzzTenant) {
			if d.Entity == "" {
				t.Fatalf("detection with empty entity stored: %+v", d)
			}
		}
	})
}
