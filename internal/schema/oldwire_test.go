// SPDX-License-Identifier: LicenseRef-probectl-TBD

package schema

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// TestOldWireFixturesDecode pins replay compatibility for bus/RPC payloads that
// were serialized before later additive fields existed. The fixtures are real
// protobuf bytes under testdata/oldwire; current generated code must continue to
// decode them and must surface absent fields as protobuf defaults.
func TestOldWireFixturesDecode(t *testing.T) {
	t.Run("result", func(t *testing.T) {
		var r resultv1.Result
		readOldWire(t, "result_v1_result.pb", &r)
		if r.GetTenantId() != "tenant-old" || r.GetAgentId() != "agent-old" {
			t.Fatalf("identity = %q/%q", r.GetTenantId(), r.GetAgentId())
		}
		if r.GetCanaryType() != "http" || !r.GetSuccess() || r.GetMetrics()["rtt.avg.ms"] != 42 {
			t.Fatalf("decoded result lost old semantics: %+v", &r)
		}
		if r.GetResultId() != "" {
			t.Fatalf("old result wire must default additive result_id to empty, got %q", r.GetResultId())
		}
	})

	t.Run("bgp", func(t *testing.T) {
		var ev bgpv1.BGPEvent
		readOldWire(t, "bgp_v1_event.pb", &ev)
		if ev.GetTenantId() != "tenant-old" || ev.GetEventType() != bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE {
			t.Fatalf("decoded BGP event lost identity/type: %+v", &ev)
		}
		if ev.GetPrefix() != "203.0.113.0/24" || ev.GetNewOriginAsn() != 64512 || ev.GetOldOriginAsn() != 64500 {
			t.Fatalf("decoded BGP subject/origin changed: %+v", &ev)
		}
	})

	t.Run("flow", func(t *testing.T) {
		var batch flowv1.FlowBatch
		readOldWire(t, "flow_v1_batch.pb", &batch)
		if len(batch.GetFlows()) != 1 {
			t.Fatalf("flows = %d, want 1", len(batch.GetFlows()))
		}
		f := batch.GetFlows()[0]
		if f.GetTenantId() != "tenant-old" || f.GetFlowProtocol() != "ipfix" || f.GetBytes() != 123456 {
			t.Fatalf("decoded flow changed: %+v", f)
		}
		if f.GetBytesScaled() != 0 || f.GetPacketsScaled() != 0 || f.GetSourceAsn() != 0 {
			t.Fatalf("old flow wire must default additive analytics/enrichment fields to zero: %+v", f)
		}
	})

	t.Run("device", func(t *testing.T) {
		var batch devicev1.DeviceMetricBatch
		readOldWire(t, "device_v1_batch.pb", &batch)
		if len(batch.GetMetrics()) != 1 {
			t.Fatalf("metrics = %d, want 1", len(batch.GetMetrics()))
		}
		m := batch.GetMetrics()[0]
		if m.GetTenantId() != "tenant-old" || m.GetSource() != "snmp" || m.GetIfName() != "xe-0/0/0" {
			t.Fatalf("decoded device metric changed: %+v", m)
		}
	})

	t.Run("ebpf", func(t *testing.T) {
		var batch ebpfv1.FlowBatch
		readOldWire(t, "ebpf_v1_batch.pb", &batch)
		if len(batch.GetFlows()) != 1 || len(batch.GetEdges()) != 1 {
			t.Fatalf("flows/edges = %d/%d, want 1/1", len(batch.GetFlows()), len(batch.GetEdges()))
		}
		if batch.GetFlows()[0].GetWorkload() != "payments-api" || batch.GetEdges()[0].GetDestination() != "postgres" {
			t.Fatalf("decoded eBPF batch changed: %+v", &batch)
		}
		if len(batch.GetL7Calls()) != 0 {
			t.Fatalf("old eBPF wire must default additive L7 calls to empty, got %d", len(batch.GetL7Calls()))
		}
	})

	t.Run("agent", func(t *testing.T) {
		var resp agentv1.RegisterResponse
		readOldWire(t, "agent_v1_register_response.pb", &resp)
		if resp.GetAgentId() != "agent-old" || resp.GetTenantId() != "tenant-old" || resp.GetConfigEpoch() != 41 {
			t.Fatalf("decoded agent register response changed: %+v", &resp)
		}
		if resp.GetControlVersion() != "" || resp.GetProtocolVersion() != "" ||
			len(resp.GetAcceptedCapabilities()) != 0 || len(resp.GetServerCapabilities()) != 0 {
			t.Fatalf("old agent wire must default additive capability fields to empty: %+v", &resp)
		}
	})
}

func readOldWire(t *testing.T, name string, into proto.Message) {
	t.Helper()
	path := filepath.Join("testdata", "oldwire", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) == 0 {
		t.Fatalf("%s is empty", path)
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(b, into); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
}
