package otel

import (
	"testing"

	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
)

func TestFlowAttributesConformToConventions(t *testing.T) {
	f := &ebpfv1.Flow{
		TenantId: "t1", AgentId: "a1", Host: "node-1",
		SourceAddress: "10.0.0.1", SourcePort: 54321,
		DestinationAddress: "10.0.0.2", DestinationPort: 443,
		NetworkTransport: "tcp", NetworkType: "ipv4",
		Direction: "egress", ProcessName: "curl", ContainerId: "abc",
	}
	attrs := FlowAttributes(f)
	for k := range attrs {
		if !KnownAttributes[k] {
			t.Errorf("attribute %q is not an OTel/probectl convention name (invented attribute)", k)
		}
	}
	if attrs[AttrTenantID] != "t1" || attrs[AttrDestinationPort] != "443" || attrs[AttrNetworkTransport] != "tcp" {
		t.Errorf("unexpected mapping: %v", attrs)
	}
}

func TestFlowAttributesOmitsEmptyOptionals(t *testing.T) {
	attrs := FlowAttributes(&ebpfv1.Flow{TenantId: "t", AgentId: "a"})
	if _, ok := attrs[AttrSourcePort]; ok {
		t.Error("source.port should be omitted when zero")
	}
	if len(attrs) != 2 {
		t.Errorf("want only the 2 identity attrs, got %v", attrs)
	}
}
