package otel

import (
	"testing"

	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// TestAllSignalMappingsConform is the S22 cross-signal conformance check: every
// signal type's attribute mapping may emit ONLY OTel-standard or probectl.* names
// (the S6 ResultAttributes discipline, now enforced across all planes), and each
// carries the tenant as the outermost scope (F50).
func TestAllSignalMappingsConform(t *testing.T) {
	mappings := map[string]map[string]string{
		"result": ResultAttributes(&resultv1.Result{
			TenantId: "t", AgentId: "a", CanaryType: "icmp",
			ServerAddress: "x", ServerPort: 443, NetworkTransport: "tcp", NetworkProtocolName: "http",
		}),
		"flow": FlowAttributes(&ebpfv1.Flow{
			TenantId: "t", AgentId: "a", Host: "h",
			SourceAddress: "1.1.1.1", SourcePort: 5, DestinationAddress: "2.2.2.2", DestinationPort: 443,
			NetworkTransport: "tcp", NetworkType: "ipv4", Direction: "egress", ProcessName: "p", ContainerId: "c",
		}),
		"l7": L7CallAttributes(&ebpfv1.L7Call{
			TenantId: "t", AgentId: "a", Protocol: "grpc", Method: "svc/M", Status: "0", Encrypted: true,
		}),
		"bgp": BGPEventAttributes(&bgpv1.BGPEvent{
			TenantId: "t", EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
			Severity: bgpv1.Severity_SEVERITY_CRITICAL, Confidence: 0.9, Prefix: "192.0.2.0/24",
			NewOriginAsn: 64500, PeerAsn: 65000, RpkiStatus: bgpv1.RpkiStatus_RPKI_STATUS_INVALID,
			Collector: "rrc00", PeerAddress: "203.0.113.1",
		}),
		"path": PathAttributes(PathSummary{
			TenantID: "t", Target: "example.com", TargetIP: "93.184.216.34", Mode: "icmp",
			HopCount: 12, DestinationReached: true,
		}),
	}

	for signal, attrs := range mappings {
		if len(attrs) == 0 {
			t.Errorf("%s: empty attribute map", signal)
		}
		for k := range attrs {
			if !KnownAttributes[k] {
				t.Errorf("%s: attribute %q is not an OTel/probectl convention name (invented attribute)", signal, k)
			}
		}
		if attrs[AttrTenantID] != "t" {
			t.Errorf("%s: missing tenant scope (%s)", signal, AttrTenantID)
		}
	}
}
