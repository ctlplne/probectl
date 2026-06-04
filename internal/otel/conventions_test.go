package otel

import (
	"testing"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// TestResultAttributesConformToConventions is the semantic-convention conformance
// check (S6 Done-when): the core Result->attribute mapping must only ever emit
// OTel-standard or probectl.* names, never an invented attribute where an OTel
// convention exists. Runs in CI (test-go).
func TestResultAttributesConformToConventions(t *testing.T) {
	r := &resultv1.Result{
		TenantId:            "tenant-1",
		AgentId:             "agent-1",
		CanaryType:          "icmp",
		ServerAddress:       "example.com",
		ServerPort:          443,
		NetworkTransport:    "tcp",
		NetworkProtocolName: "http",
	}
	attrs := ResultAttributes(r)
	for k := range attrs {
		if !KnownAttributes[k] {
			t.Errorf("attribute %q is not an OTel/probectl convention name (invented attribute)", k)
		}
	}

	want := map[string]string{
		AttrTenantID:         "tenant-1",
		AttrAgentID:          "agent-1",
		AttrCanaryType:       "icmp",
		AttrServerAddress:    "example.com",
		AttrServerPort:       "443",
		AttrNetworkTransport: "tcp",
		AttrNetworkProtocol:  "http",
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("%s = %q, want %q", k, attrs[k], v)
		}
	}
}

func TestResultAttributesOmitsEmptyOptionals(t *testing.T) {
	attrs := ResultAttributes(&resultv1.Result{TenantId: "t", AgentId: "a", CanaryType: "noop"})
	if _, ok := attrs[AttrServerAddress]; ok {
		t.Error("server.address should be omitted when empty")
	}
	if _, ok := attrs[AttrServerPort]; ok {
		t.Error("server.port should be omitted when zero")
	}
	if len(attrs) != 3 {
		t.Errorf("expected only the 3 identity attributes, got %v", attrs)
	}
}
