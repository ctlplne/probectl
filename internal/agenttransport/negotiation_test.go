// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agenttransport

import (
	"slices"
	"testing"
)

func TestAcceptedCapabilitiesIntersectsRequestedAndKnown(t *testing.T) {
	got := acceptedCapabilities([]string{"future-probe-v2", "icmp", "dns", "browser", "icmp", ""})
	want := []string{"browser", "dns", "icmp"}
	if !slices.Equal(got, want) {
		t.Fatalf("acceptedCapabilities = %v, want %v", got, want)
	}
}

func TestServerCapabilitiesReturnsCopy(t *testing.T) {
	got := copyServerCapabilities()
	if !slices.Contains(got, "agent.stream_results") || !slices.Contains(got, "tenant.identity.mtls.v1") {
		t.Fatalf("server capabilities missing core behavior: %v", got)
	}
	got[0] = "mutated"
	if slices.Contains(copyServerCapabilities(), "mutated") {
		t.Fatal("server capability slice was not copied")
	}
}

func TestServerCapabilitiesAdvertiseVersionedBehaviors(t *testing.T) {
	got := copyServerCapabilities()
	if !slices.IsSorted(got) {
		t.Fatalf("server capabilities must be stable/sorted, got %v", got)
	}
	for _, want := range []string{
		"agent.register",
		"agent.attest",
		"agent.heartbeat",
		"agent.stream_results",
		"agent.poll_coordination",
		"agent.report_endpoint",
		"result.schema.v1",
		"tenant.identity.mtls.v1",
		"stream_results.freshness.v1",
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("server capability %q not advertised in %v", want, got)
		}
	}
}
