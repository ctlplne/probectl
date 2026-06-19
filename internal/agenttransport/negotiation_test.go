// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agenttransport

import (
	"slices"
	"testing"
)

func TestAcceptedCapabilitiesIntersectsRequestedAndKnown(t *testing.T) {
	got := acceptedCapabilities([]string{"future-probe-v2", "icmp", "dns", "icmp", ""})
	want := []string{"dns", "icmp"}
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
