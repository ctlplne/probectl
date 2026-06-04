package agenttransport

import (
	"testing"

	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
)

// TestServiceDescriptorMethods guards the wire contract: the generated
// AgentService must expose exactly these RPCs. A removed or renamed RPC fails
// here, complementing the `buf breaking` check in CI.
func TestServiceDescriptorMethods(t *testing.T) {
	want := []string{"Register", "Attest", "Heartbeat", "StreamConfig", "StreamResults", "PollCoordination", "ReportEndpoint"}

	got := map[string]bool{}
	for _, m := range agentv1.AgentService_ServiceDesc.Methods {
		got[m.MethodName] = true
	}
	for _, s := range agentv1.AgentService_ServiceDesc.Streams {
		got[s.StreamName] = true
	}

	if len(got) != len(want) {
		t.Errorf("RPC set has %d methods, want %d: %v", len(got), len(want), got)
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing RPC %q", name)
		}
	}
}
