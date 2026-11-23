// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"cmp"
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
	t.Run("sparse evidence distinguishes quiet from unsupported pressure", func(t *testing.T) {
		input := current
		input.ObservedRecords = thresholds.MinObservedRecords - 1
		if finding, err := EvaluateDDoS(ctx, reference, input, thresholds, 1<<20); err != nil || finding != nil {
			t.Fatal("sparse quiet traffic should remain a quiet comparison", finding, err)
		}
		input.Packets = "4000"
		if finding, err := EvaluateDDoS(ctx, reference, input, thresholds, 1<<20); !errors.Is(err, ErrDDoSRecordSupport) || finding != nil {
			t.Fatal("sparse pressure was treated as quiet or classified without enough records", finding, err)
		}
		input.ObservedRecords++
		if finding, err := EvaluateDDoS(ctx, reference, input, thresholds, 1<<20); err != nil || finding == nil || finding.Class != DDoSVolumetric {
			t.Fatal("pressure with the exact minimum original records should qualify", finding, err)
		}
	})

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
	current.UDPPackets, current.UnclassifiedTCPPackets, current.UnclassifiedUDPPackets = "600", "401", "0"
	if got, err := EvaluateDDoS(ctx, reference, current, thresholds, 1<<20); got != nil || !errors.Is(err, ErrDDoSCoverage) {
		t.Fatal("unclassified TCP cannot overlap the UDP population", err)
	}
	current.UnclassifiedTCPPackets, current.UnclassifiedUDPPackets = "0", "601"
	if got, err := EvaluateDDoS(ctx, reference, current, thresholds, 1<<20); got != nil || !errors.Is(err, ErrDDoSCoverage) {
		t.Fatal("unclassified UDP cannot exceed the UDP population", err)
	}
	current.UnclassifiedUDPPackets, current.UnclassifiedTransportPackets = "0", "401"
	if got, err := EvaluateDDoS(ctx, reference, current, thresholds, 1<<20); got != nil || !errors.Is(err, ErrDDoSCoverage) {
		t.Fatal("unclassified transport must fit alongside measured UDP in the total", err)
	}
}

func TestDDoSReflectionComparesEachServiceToItsOwnReference(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	start := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	before := DDoSObservation{TenantID: owner, Scope: "owned host", Target: netip.MustParsePrefix("192.0.2.1/32"), Direction: "ingress",
		From: start, To: start.Add(5 * time.Second), Citation: "reference", Complete: true,
		Bytes: "200000", Packets: "2500", SYNOnlyPackets: "0", UDPPackets: "2200", ObservedRecords: 100, ObservedAddresses: 1,
		Reflection: []ReflectionObservation{{Service: "dns", Packets: "1800"}, {Service: "ntp", Packets: "400"}}}
	after := before
	after.From, after.To, after.Citation = before.From.AddDate(0, 0, 7), before.To.AddDate(0, 0, 7), "current"
	after.Bytes, after.Packets, after.UDPPackets = "310000", "3200", "3000"
	after.Reflection = []ReflectionObservation{{Service: "dns", Packets: "1800"}, {Service: "ntp", Packets: "1200"}}
	limits := DDoSThresholds{BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
		VectorShareBasisPoints: 3500, MinObservedRecords: 50, MinObservedAddresses: 2}
	finding, err := EvaluateDDoS(ctx, before, after, limits, 1<<20)
	if err != nil || finding == nil || finding.Class != DDoSReflection || finding.Service != "ntp" || finding.ContributingPackets != "1200" {
		t.Fatalf("the growing vector must win over larger steady background, got %+v, %v", finding, err)
	}
	limits.VectorShareBasisPoints = 4000
	finding, err = EvaluateDDoS(ctx, before, after, limits, 1<<20)
	if err != nil || finding == nil || finding.Class != DDoSVolumetric {
		t.Fatalf("a growing below-share vector cannot corroborate pressure, got %+v, %v", finding, err)
	}
}

func TestDDoSDetectsMeasuredVectorWhenPopulationVolumeFalls(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	start := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	for _, vector := range []DDoSClass{DDoSSYN, DDoSReflection} {
		t.Run(string(vector), func(t *testing.T) {
			for _, scenario := range []struct {
				name, baseline, previouslyUnknown, packets, total string
				records                                           int
				positive                                          bool
				wantErr                                           error
				historicalInconclusive                            bool
			}{
				{"falling total", "1900", "0", "2800", "4000", 50, true, nil, false},
				{"flat total at vector floor", "1900", "0", "2500", "4200", 50, true, nil, false},
				{"below packet floor", "1900", "0", "2499", "4000", 50, false, nil, false},
				{"below vector share", "1900", "0", "2500", "4300", 50, false, nil, false},
				{"insufficient vector growth", "2400", "0", "2800", "4000", 50, false, nil, false},
				{"steady vector", "2800", "0", "2800", "4000", 50, false, nil, false},
				{"historical classification missing", "0", "2400", "2800", "4000", 50, false, nil, true},
				{"measured growth above the historical upper bound", "0", "100", "2800", "4000", 50, true, nil, false},
				{"missing history below the current vector floor", "0", "2400", "2499", "4000", 50, false, nil, false},
				{"below observation floor", "1900", "0", "2800", "4000", 49, false, ErrDDoSRecordSupport, false},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					before := DDoSObservation{TenantID: owner, Scope: "owned host", Target: netip.MustParsePrefix("192.0.2.1/32"), Direction: "ingress",
						From: start, To: start.Add(5 * time.Second), Citation: "reference", Complete: true,
						Bytes: "420000", Packets: "4200", SYNOnlyPackets: "0", UDPPackets: "0", ObservedRecords: 50, ObservedAddresses: 1}
					after := before
					after.From, after.To, after.Citation = before.From.AddDate(0, 0, 7), before.To.AddDate(0, 0, 7), "current"
					after.Bytes, after.Packets, after.ObservedRecords = "400000", scenario.total, scenario.records
					service := ""
					if vector == DDoSSYN {
						before.SYNOnlyPackets, before.UnclassifiedTCPPackets = scenario.baseline, scenario.previouslyUnknown
						after.SYNOnlyPackets = scenario.packets
					} else {
						service = "dns"
						before.UDPPackets = scenario.baseline
						if scenario.previouslyUnknown != "0" {
							before.UDPPackets = scenario.previouslyUnknown
						}
						before.UnclassifiedUDPPackets = scenario.previouslyUnknown
						before.Reflection = []ReflectionObservation{{Service: service, Packets: scenario.baseline}}
						after.UDPPackets = scenario.packets
						after.Reflection = []ReflectionObservation{{Service: service, Packets: scenario.packets}}
					}
					limits := DDoSThresholds{BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
						VectorShareBasisPoints: 5900, MinObservedRecords: 50, MinObservedAddresses: 2}
					got, err := EvaluateDDoS(ctx, before, after, limits, 1<<20)
					if !errors.Is(err, scenario.wantErr) || (got != nil) != scenario.positive {
						t.Fatalf("expected finding=%t and err=%v, got %+v, %v", scenario.positive, scenario.wantErr, got, err)
					}
					if got != nil && (got.Class != vector || got.Service != service || got.ContributingPackets != scenario.packets ||
						got.ReferencePackets != before.Packets || got.CurrentPackets != after.Packets) {
						t.Fatalf("finding must cite the measured vector and original population, got %+v", got)
					}

					limits.MixedVectors = true
					finding, err := EvaluateDDoS(ctx, before, after, limits, 1<<20)
					want := scenario.wantErr
					if scenario.historicalInconclusive {
						want = ErrDDoSHistoricalClassification
					}
					if !errors.Is(err, want) || (finding != nil) != scenario.positive {
						t.Fatalf("short-window comparison: expected finding=%t and err=%v, got %+v, %v", scenario.positive, want, finding, err)
					}
				})
			}
		})
	}
}

func TestDDoSCurrentClassificationRequiresDisjointPacketEvidence(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	start := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	reference := DDoSObservation{TenantID: owner, Scope: "owned host", Target: netip.MustParsePrefix("192.0.2.1/32"), Direction: "ingress",
		From: start, To: start.Add(5 * time.Second), Citation: "reference", Complete: true,
		Bytes: "800000", Packets: "8000", SYNOnlyPackets: "0", UDPPackets: "0", ObservedRecords: 50, ObservedAddresses: 1}
	for _, test := range []struct {
		name, previousSYN, syn, dns, noFlags, noPorts, noTransport string
		udp                                                        string
		share                                                      int
		wantError                                                  error
		wantClass                                                  DDoSClass
	}{
		{name: "entire current population lacks transport", noTransport: "8000", wantError: ErrDDoSCurrentClassification},
		{name: "small unclassified residue cannot meet any floor", noFlags: "500", noPorts: "500", noTransport: "500", udp: "500"},
		{name: "current missing flags cannot hide growth over higher history", previousSYN: "6500", noFlags: "5000"},
		{name: "missing TCP flags can hide a single growing vector", syn: "1000", noFlags: "4000", wantError: ErrDDoSCurrentClassification},
		{name: "missing UDP ports can complete a mix", syn: "2500", dns: "1900", noPorts: "600", udp: "2500",
			wantError: ErrDDoSCurrentClassification},
		{name: "shared transport cannot fill two deficits twice", syn: "2300", dns: "2300", noTransport: "300", udp: "2300", share: 4500},
		{name: "shared transport fills both deficits at the exact floor", syn: "2300", dns: "2300", noTransport: "400", udp: "2300",
			share: 4500, wantError: ErrDDoSCurrentClassification},
		{name: "measured pressure survives unrelated omitted classification", syn: "6000", noTransport: "500", wantClass: DDoSSYN},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, current := reference, reference
			before.SYNOnlyPackets = cmp.Or(test.previousSYN, "0")
			current.From, current.To, current.Citation = before.From.AddDate(0, 0, 7), before.To.AddDate(0, 0, 7), "current"
			current.SYNOnlyPackets, current.UDPPackets = cmp.Or(test.syn, "0"), cmp.Or(test.udp, "0")
			current.UnclassifiedTCPPackets, current.UnclassifiedUDPPackets, current.UnclassifiedTransportPackets = test.noFlags, test.noPorts, test.noTransport
			if test.dns != "" {
				current.Reflection = []ReflectionObservation{{Service: "dns", Packets: test.dns}}
			}
			limits := DDoSThresholds{BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
				VectorShareBasisPoints: cmp.Or(test.share, 6000), MinObservedRecords: 50, MinObservedAddresses: 2, MixedVectors: true}
			got, err := EvaluateDDoS(ctx, before, current, limits, 1<<20)
			if !errors.Is(err, test.wantError) || (got != nil) != (test.wantClass != "") || got != nil && got.Class != test.wantClass {
				t.Fatalf("want class %q and error %v, got %+v and %v", test.wantClass, test.wantError, got, err)
			}
		})
	}
}

func TestDDoSApplicationQualifiesDegradationWithAHealthyReference(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	start := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	earlier := DDoSObservation{TenantID: owner, Scope: "owned service", Target: netip.MustParsePrefix("192.0.2.1/32"), Direction: "ingress",
		From: start, To: start.Add(5 * time.Second), Citation: "owned reference", Complete: true,
		Bytes: "90000", Packets: "900", ApplicationBytes: "90000", ApplicationPackets: "900"}
	current := earlier
	current.From, current.To, current.Citation = earlier.From.AddDate(0, 0, 7), earlier.To.AddDate(0, 0, 7), "current observation"
	current.Bytes, current.Packets, current.ApplicationBytes, current.ApplicationPackets = "360000", "3600", "360000", "3600"
	previousApp := DDoSApplicationWindow{TenantID: owner, Target: earlier.Target, From: earlier.From, To: earlier.To,
		Requests: 30, Successes: 20, P95: 100 * time.Millisecond, Digest: strings.Repeat("a", 64)}
	currentApp := previousApp
	currentApp.From, currentApp.To = current.From, current.To
	currentApp.Requests, currentApp.Successes, currentApp.P95 = 120, 120, 50*time.Millisecond

	finding := &DDoSDetection{Class: DDoSVolumetric}
	limits := DDoSThresholds{BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000}
	got, app, err := QualifyDDoSApplication(ctx, earlier, current, previousApp, currentApp, finding, limits, 1<<20)
	if err != nil || got != finding || app == nil || app.State != DDoSApplicationAmbiguous {
		t.Fatalf("recovery from an unhealthy reference must leave flow pressure inconclusive, got %+v, %v", app, err)
	}

	previousApp.Successes = previousApp.Requests
	currentApp.Requests, currentApp.Successes, currentApp.P95 = 30, 30, 6*time.Second
	got, app, err = QualifyDDoSApplication(ctx, earlier, current, previousApp, currentApp, finding, limits, 1<<20)
	if err != nil || got != finding || app == nil || app.State != DDoSApplicationDegraded || app.Current.P95 != 6*time.Second {
		t.Fatalf("completed slow requests must corroborate their original window, got %+v, %v", app, err)
	}

	currentApp.Requests, currentApp.Successes = 120, 120
	got, app, err = QualifyDDoSApplication(ctx, earlier, current, previousApp, currentApp, finding, limits, 1<<20)
	if err != nil || got != finding || app == nil || app.State != DDoSApplicationOverload {
		t.Fatalf("proportionate slow requests must leave pressure inconclusive, got %+v, %v", app, err)
	}

	earlier.Bytes, earlier.Packets, earlier.ApplicationBytes, earlier.ApplicationPackets = "300000", "3000", "300000", "3000"
	for _, scenario := range []struct {
		requests int
		state    string
	}{
		{31, DDoSApplicationDegraded},
		{36, DDoSApplicationOverload},
	} {
		currentApp.Requests, currentApp.Successes = scenario.requests, scenario.requests
		got, app, err := QualifyDDoSApplication(ctx, earlier, current, previousApp, currentApp, finding, limits, 1<<20)
		if err != nil || got != finding || app == nil || app.State != scenario.state {
			t.Fatalf("20%% traffic growth with %d completed requests must yield %q, got %+v, %v", scenario.requests, scenario.state, app, err)
		}
	}
}

func TestDDoSApplicationRequiresPressureOnTheDegradedListener(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	start := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	before := DDoSObservation{TenantID: owner, Scope: "owned service", Target: netip.MustParsePrefix("192.0.2.1/32"),
		Direction: "ingress", From: start, To: start.Add(5 * time.Second), Citation: "reference", Complete: true,
		Bytes: "220000", Packets: "2500", ApplicationBytes: "140000", ApplicationPackets: "1700",
		SYNOnlyPackets: "0", UDPPackets: "0", ObservedRecords: 80, ObservedAddresses: 1}
	previousApp := DDoSApplicationWindow{TenantID: owner, Target: before.Target, From: before.From, To: before.To,
		Requests: 30, Successes: 30, P95: 25 * time.Millisecond, Digest: strings.Repeat("a", 64)}
	limits := DDoSThresholds{BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
		VectorShareBasisPoints: 6000, MinObservedRecords: 50, MinObservedAddresses: 2}
	for _, scenario := range []struct {
		name, bytes, packets, listenerBytes, listenerPackets, state string
		referenceFailures                                           int
	}{
		{"unrelated load below both floors", "290000", "3500", "140000", "1700", DDoSApplicationAmbiguous, 0},
		{"unrelated load above both floors", "400000", "4500", "140000", "1700", DDoSApplicationResidual, 0},
		{"listener byte pressure", "440000", "2500", "360000", "1700", DDoSApplicationDegraded, 0},
		{"listener packet pressure", "220000", "4400", "140000", "3600", DDoSApplicationDegraded, 0},
		{"independent pressure outside degraded reference listener", "400000", "4500", "140000", "1700", DDoSApplicationResidual, 8},
		{"subthreshold traffic outside degraded reference listener", "290000", "3500", "140000", "1700", DDoSApplicationAmbiguous, 8},
		{"degraded reference cannot corroborate pressure at its own listener", "440000", "2500", "360000", "1700", DDoSApplicationAmbiguous, 8},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			after := before
			after.From, after.To, after.Citation = before.From.AddDate(0, 0, 7), before.To.AddDate(0, 0, 7), "current"
			after.Bytes, after.Packets = scenario.bytes, scenario.packets
			after.ApplicationBytes, after.ApplicationPackets = scenario.listenerBytes, scenario.listenerPackets
			earlierApp := previousApp
			earlierApp.Successes -= scenario.referenceFailures
			latestApp := previousApp
			latestApp.From, latestApp.To, latestApp.Successes = after.From, after.To, 20
			latestApp.P95, latestApp.Digest = 80*time.Millisecond, strings.Repeat("b", 64)
			finding, err := EvaluateDDoS(ctx, before, after, limits, 1<<20)
			if err != nil || finding == nil || finding.Class != DDoSVolumetric {
				t.Fatalf("fixture must reach volume qualification, got %+v, %v", finding, err)
			}
			got, app, err := QualifyDDoSApplication(ctx, before, after, earlierApp, latestApp, finding, limits, 1<<20)
			if err != nil || got != finding || app == nil || app.State != scenario.state {
				t.Fatalf("qualifier state want %q, got %+v, %v", scenario.state, app, err)
			}
		})
	}
}

func TestDDoSApplicationRequiresMeasuredOutsideTraffic(t *testing.T) {
	const floor = "2500"
	reference := applicationTrafficWindow{total: "4000", listener: "3200"}
	current := applicationTrafficWindow{total: "4000", listener: "1200"}
	for _, scenario := range []struct {
		name               string
		reference, current applicationTrafficWindow
		definite, possible bool
	}{
		{"known outside growth", reference, current, true, true},
		{"unreported current port", reference, applicationTrafficWindow{"4000", "1200", "2800"}, false, true},
		{"unreported reference port", applicationTrafficWindow{"4000", "800", "2400"}, current, false, true},
		{"enough known despite missing ports", reference, applicationTrafficWindow{"4300", "1300", "200"}, true, true},
		{"known quiet", reference, reference, false, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			parser := decimalSeasonalTraining{work: 1 << 20}
			got, err := compareApplicationTraffic(&parser, applicationDemand{previous: 80, current: 30}, scenario.reference, scenario.current, floor, 2000)
			if err != nil || got.residualPressure != scenario.definite || got.possibleResidualPressure != scenario.possible {
				t.Fatal("unexpected outside-traffic bounds", got, err)
			}
		})
	}
}
