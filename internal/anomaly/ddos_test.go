// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDDoSClassificationKeepsPassiveMeasuredEvidence(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	first := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	reference := DDoSObservation{
		TenantID: owner, Scope: "owned prefix evidence", Target: netip.MustParsePrefix("192.0.2.0/24"), Direction: "ingress",
		From: first, To: first.Add(time.Minute), Citation: "scoped reference", Complete: true,
		Bytes: "9007199254740993", Packets: "1000", SYNOnlyPackets: "0", UDPPackets: "300", ObservedRecords: 100, ObservedAddresses: 2,
	}
	current := reference
	current.From, current.To, current.Citation = reference.To, reference.To.Add(time.Minute), "scoped observation"
	thresholds := DDoSThresholds{BytesFloor: "9007199254740994", PacketsFloor: "2500", GrowthBasisPoints: 2000,
		VectorShareBasisPoints: 6000, MinObservedRecords: 50, MinObservedAddresses: 8}

	if finding, err := EvaluateDDoS(ctx, reference, current, thresholds, 1<<20); err != nil || finding != nil {
		t.Fatal("stable measured traffic created a finding", finding, err)
	}

	tests := []struct {
		name, syn, udp, service string
		addresses               int
		want                    DDoSClass
	}{
		{"SYN flag pressure", "3300", "0", "", 2, DDoSSYN},
		{"DNS source service association", "0", "3500", "dns", 2, DDoSReflection},
		{"NTP source service association", "0", "3500", "ntp", 2, DDoSReflection},
		{"memcached source service association", "0", "3500", "memcached", 2, DDoSReflection},
		{"CLDAP source service association", "0", "3500", "cldap", 2, DDoSReflection},
		{"SSDP source service association", "0", "3500", "ssdp", 2, DDoSReflection},
		{"distributed protected destinations", "0", "1000", "", 10, DDoSPrefixSpread},
		{"volume pressure", "0", "1000", "", 2, DDoSVolumetric},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := current
			input.Bytes, input.Packets, input.SYNOnlyPackets, input.UDPPackets = "9007199254740994", "4000", tc.syn, tc.udp
			input.ObservedAddresses = tc.addresses
			if tc.service != "" {
				input.Reflection = []ReflectionObservation{{Service: tc.service, Packets: "3200"}}
			}
			got, err := EvaluateDDoS(ctx, reference, input, thresholds, 1<<20)
			if err != nil || got == nil || got.Class != tc.want || got.Service != tc.service ||
				got.Confidence == "" || got.EvidenceBasis == "" || got.CurrentBytes != input.Bytes || got.ReferenceBytes != reference.Bytes ||
				got.CurrentCitation != input.Citation || got.ReferenceCitation != reference.Citation {
				t.Fatal("the comparison lost its exact measurements, class or provenance", got, err)
			}
		})
	}
}

func TestDDoSCannotBorrowForeignOrIncompleteEvidence(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	const sibling = "aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	first := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	reference := DDoSObservation{
		TenantID: owner, Scope: "owned prefix evidence", Target: netip.MustParsePrefix("192.0.2.0/24"), Direction: "ingress",
		From: first, To: first.Add(time.Minute), Citation: "owned reference", Complete: true,
		Bytes: "150000", Packets: "1000", SYNOnlyPackets: "0", UDPPackets: "0", ObservedRecords: 100, ObservedAddresses: 2,
	}
	current := reference
	current.From, current.To, current.Citation = reference.To, reference.To.Add(time.Minute), "owned current"
	thresholds := DDoSThresholds{BytesFloor: "100000", PacketsFloor: "1000", GrowthBasisPoints: 500,
		VectorShareBasisPoints: 6000, MinObservedRecords: 20, MinObservedAddresses: 8}
	foreign := current
	foreign.TenantID = sibling
	if got, err := EvaluateDDoS(ctx, reference, foreign, thresholds, 1<<20); got != nil || !errors.Is(err, ErrCrossTenantFeature) {
		t.Fatal("the scanner accepted evidence from its sibling tenant", err)
	}
	current.Complete = false
	if got, err := EvaluateDDoS(ctx, reference, current, thresholds, 1<<20); got != nil || !errors.Is(err, ErrDDoSCoverage) {
		t.Fatal("an incomplete source window became a finding", err)
	}
	current.Complete = true
	current.UDPPackets = "1100"
	if got, err := EvaluateDDoS(ctx, reference, current, thresholds, 1<<20); got != nil || !errors.Is(err, ErrDDoSCoverage) {
		t.Fatal("a measured subset cannot exceed its complete population", err)
	}
}

func TestDDoSApplicationDoesNotInferCurrentDegradationFromAnUnhealthyReference(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	start := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	earlier := DDoSObservation{TenantID: owner, Scope: "owned service", Target: netip.MustParsePrefix("192.0.2.1/32"), Direction: "ingress",
		From: start, To: start.Add(5 * time.Second), Citation: "owned reference", Complete: true}
	current := earlier
	current.From, current.To, current.Citation = earlier.From.AddDate(0, 0, 7), earlier.To.AddDate(0, 0, 7), "current observation"
	previousApp := DDoSApplicationWindow{TenantID: owner, Target: earlier.Target, From: earlier.From, To: earlier.To,
		Requests: 30, Successes: 20, P95: 100 * time.Millisecond, Digest: strings.Repeat("a", 64)}
	currentApp := previousApp
	currentApp.From, currentApp.To = current.From, current.To
	currentApp.Requests, currentApp.Successes, currentApp.P95 = 120, 120, 50*time.Millisecond

	finding := &DDoSDetection{Class: DDoSVolumetric}
	got, app, err := QualifyDDoSApplication(ctx, earlier, current, previousApp, currentApp, finding, DDoSThresholds{}, 1<<20)
	if err != nil || got != finding || app == nil || app.State != DDoSApplicationAmbiguous {
		t.Fatalf("recovery from an unhealthy reference must leave flow pressure inconclusive, got %+v, %v", app, err)
	}
}
