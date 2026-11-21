// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDDoSWeeklyReferenceKeepsOriginalClockThroughAnOutlier(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	to := time.Date(2026, 1, 26, 13, 5, 15, 0, time.UTC)
	current := DDoSObservation{TenantID: owner, Scope: "owned host", Target: netip.MustParsePrefix("192.0.2.1/32"),
		Direction: "ingress", From: to.Add(-5 * time.Second), To: to, Complete: true, Citation: "current"}
	prior := make([]DDoSObservation, 0, 4)
	for i, sample := range []struct{ bytes, packets, citation string }{
		{"99999999999", "88888888", "previous-week-outlier"},
		{"100000", "1000", "two-weeks"},
		{"101000", "1050", "three-weeks"},
		{"98000", "950", "four-weeks"},
	} {
		ref := current
		ref.From, ref.To = current.From.AddDate(0, 0, -7*(i+1)), current.To.AddDate(0, 0, -7*(i+1))
		ref.Bytes, ref.Packets, ref.Citation = sample.bytes, sample.packets, sample.citation
		ref.SYNOnlyPackets, ref.UDPPackets, ref.ObservedRecords = "0", "0", 64
		prior = append(prior, ref)
	}
	selected, err := SelectDDoSWeeklyReference(ctx, current, prior, 1<<20)
	if err != nil || selected.Citation != "two-weeks" || !selected.To.Equal(prior[1].To) {
		t.Fatalf("expected the newer of two equally representative original windows, got %+v (%v)", selected, err)
	}
	reverse := slices.Clone(prior)
	slices.Reverse(reverse)
	ordered, err := SelectDDoSWeeklyReference(ctx, current, reverse, 1<<20)
	if err != nil || !ordered.To.Equal(selected.To) {
		t.Fatal("source order changed the representative original clock", ordered, err)
	}
	prior[1].Complete = false
	prior[2].Complete = false
	if _, err := SelectDDoSWeeklyReference(ctx, current, prior, 1<<20); !errors.Is(err, ErrDDoSCoverage) {
		t.Fatal("insufficient original clocks must stay unknown", err)
	}
	prior[3].TenantID = "aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"
	if _, err := SelectDDoSWeeklyReference(ctx, current, prior, 1<<20); !errors.Is(err, ErrCrossTenantFeature) {
		t.Fatal("a sibling reference must be refused", err)
	}
}

func TestDDoSWeeklyReferencePairSelectsOneOriginalWeek(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	end := time.Date(2026, 1, 26, 13, 5, 15, 0, time.UTC)
	fixture := func(at time.Time, bytes, packets, citation string) DDoSObservation {
		return DDoSObservation{TenantID: owner, Scope: "owned service", Direction: "ingress",
			Target: netip.MustParsePrefix("192.0.2.1/32"), From: at.Add(-5 * time.Second), To: at, Complete: true,
			Bytes: bytes, Packets: packets, SYNOnlyPackets: "0", UDPPackets: "0", ObservedRecords: 30, Citation: citation}
	}
	pair := func(at time.Time, bytes, packets, citation string) DDoSObservationPair {
		return DDoSObservationPair{
			Previous: fixture(at.Add(-5*time.Second), bytes, packets, citation+"-begin"),
			Current:  fixture(at, bytes, packets, citation+"-end"),
		}
	}
	current := pair(end, "440000", "4400", "current")
	prior := []DDoSObservationPair{
		pair(end.AddDate(0, 0, -7), "45000000000", "450000000", "large-outlier"),
		pair(end.AddDate(0, 0, -14), "110000", "1100", "typical"),
		pair(end.AddDate(0, 0, -21), "90000", "900", "lighter"),
	}
	// The most recent pair has the same cumulative totals as the second
	// week, but each individual window is irregular.
	prior[0].Previous.Bytes, prior[0].Previous.Packets = "210000", "2100"
	prior[0].Current.Bytes, prior[0].Current.Packets = "10000", "100"
	prior[2].Current.Bytes, prior[2].Current.Packets = "112000", "1120"
	chosen, err := SelectDDoSWeeklyReferencePair(ctx, current, prior, 1<<20)
	if err != nil || chosen.Previous.Citation != "typical-begin" || chosen.Current.Citation != "typical-end" {
		t.Fatalf("expected both original clocks from the typical week, got %+v (%v)", chosen, err)
	}
	prior[1].Previous.To = prior[1].Previous.To.Add(-time.Second)
	if _, err := SelectDDoSWeeklyReferencePair(ctx, current, prior, 1<<20); !errors.Is(err, ErrDDoSCoverage) {
		t.Fatal("a reference with nonadjacent source clocks must stay unavailable", err)
	}
}

func TestDDoSWeeklyReferenceHoldoutRecoversPressureAfterAnUnusualPriorWeek(t *testing.T) {
	const tenant = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	end := time.Date(2026, time.November, 20, 14, 15, 5, 0, time.UTC)
	current := DDoSObservation{TenantID: tenant, Scope: "owned protected host", Target: netip.MustParsePrefix("192.0.2.1/32"),
		Direction: "ingress", From: end.Add(-5 * time.Second), To: end, Citation: "current", Complete: true,
		Bytes: "420000", Packets: "4200", SYNOnlyPackets: "0", UDPPackets: "0", ObservedAddresses: 1, ObservedRecords: 200}
	weeks := make([]DDoSObservation, 0, 4)
	for i, reading := range []struct{ bytes, packets, name string }{
		{"520000", "5200", "unusual last week"}, {"90000", "900", "older w2"},
		{"115000", "1150", "older w3"}, {"100000", "1000", "older w4"},
	} {
		observed := current
		observed.From, observed.To = current.From.AddDate(0, 0, -7*(i+1)), current.To.AddDate(0, 0, -7*(i+1))
		observed.Bytes, observed.Packets, observed.Citation = reading.bytes, reading.packets, reading.name
		weeks = append(weeks, observed)
	}
	limits := DDoSThresholds{BytesFloor: "200000", PacketsFloor: "2000", GrowthBasisPoints: 1500,
		VectorShareBasisPoints: 6000, MinObservedRecords: 20, MinObservedAddresses: 2}
	before, err := EvaluateDDoS(ctx, weeks[0], current, limits, 1<<20)
	if err != nil || before != nil {
		t.Fatal("the original one-week control did not exercise missed sustained pressure", before, err)
	}
	original, err := SelectDDoSWeeklyReference(ctx, current, weeks, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	after, err := EvaluateDDoS(ctx, original, current, limits, 1<<20)
	if err != nil || after == nil || after.Class != DDoSVolumetric || after.ReferenceCitation != original.Citation ||
		original.Citation == weeks[0].Citation {
		t.Fatal("pressure did not retain a comparable historical observation", after, original, err)
	}
	for _, normal := range weeks[1:] {
		quiet := current
		quiet.Bytes, quiet.Packets = normal.Bytes, normal.Packets
		if detection, err := EvaluateDDoS(ctx, original, quiet, limits, 1<<20); err != nil || detection != nil {
			t.Fatal("the representative historical clock changed conditions for a quiet window", detection, err)
		}
	}
}
