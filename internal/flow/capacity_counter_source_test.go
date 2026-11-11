// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func capacitySourceTestInput() (context.Context, CapacityCounterSource, CapacityMeasurementWindow, []CapacityCounterObservation) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 123, time.UTC)
	source := CapacityCounterSource{TenantID: uuid.NewString(), ContextID: uuid.NewString(), DeviceID: uuid.NewString(), InterfaceID: uuid.NewString(),
		AgentID: "counter-agent", SourceRef: "192.0.2.1", SourceAssignedAt: start.Add(-time.Hour), AgentAssignedAt: start.Add(-time.Hour), InterfaceCreatedAt: start.Add(-time.Hour), PhysicalMaxBPS: 1_000_000}
	window := CapacityMeasurementWindow{From: start, To: start.Add(10 * time.Minute), MaximumPollGap: 5 * time.Minute, MemoryBytes: 128 << 20, WorkUnits: 128 << 20}
	var observations []CapacityCounterObservation
	for _, direction := range []string{"in", "out"} {
		for i := range 3 {
			value, width := uint64(1<<32-1000)+uint64(i)*30000, uint8(32)
			if direction == "out" {
				value, width = ^uint64(0)-999+uint64(i)*60000, 64
			} else {
				value %= 1 << 32
			}
			at := start.Add(time.Duration(i) * 5 * time.Minute)
			observations = append(observations, CapacityCounterObservation{Direction: direction, PollStartedAt: at, PollCompletedAt: at.Add(100 * time.Millisecond),
				Value: value, Width: width, UptimeTicks: 100000 + uint32(i)*30000, UptimeKnown: true, DiscontinuityKnown: true})
		}
	}
	return tenancy.WithTenant(context.Background(), tenancy.ID(source.TenantID)), source, window, observations
}

func TestCapacityCounterSourceUsesOriginalClocksAndExact32And64BitWraps(t *testing.T) {
	ctx, source, window, observations := capacitySourceTestInput()
	measured, err := MeasureCapacityCounterMember(ctx, source, window, observations)
	if err != nil || measured.Source() != source || CapacityCounterWindowModel() != "poll_start_counter_poll_mean_overlap" {
		t.Fatal("original source measurement failed", measured.Source(), err)
	}
	for _, direction := range []string{"in", "out"} {
		samples := measured.Samples(direction)
		bps, bytes := "800", "30000"
		if direction == "out" {
			bps, bytes = "1600", "60000"
		}
		if len(samples) != 2 {
			t.Fatal("complete common grid lost samples", samples)
		}
		for i, sample := range samples {
			if !sample.Observed || sample.Reason != "" || sample.Wrapped != (i == 0) || sample.BPSNumerator != bps || sample.BPSDenominator != "1" ||
				sample.BytesNumerator != bytes || sample.BytesDenominator != "1" || !sample.From.Equal(window.From.Add(time.Duration(i)*5*time.Minute)) || sample.To.Sub(sample.From) != 5*time.Minute {
				t.Fatal("counter words, zero discontinuity or nanosecond grid were rounded", direction, i, sample)
			}
		}
		// Projection cannot mutate the opaque grid used by billing/forecast.
		samples[0].BPSNumerator = "0"
		if measured.Samples(direction)[0].BPSNumerator != bps {
			t.Fatal("caller mutated measured facts through a public projection")
		}
	}
}

func TestCapacityCounterSourceKeepsAmbiguousClocksMissingAndResetsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func([]CapacityCounterObservation)
	}{
		{"missing uptime", "uptime_or_discontinuity_unavailable", func(p []CapacityCounterObservation) { p[1].UptimeKnown = false; p[1].UptimeTicks = 0 }},
		{"missing discontinuity", "uptime_or_discontinuity_unavailable", func(p []CapacityCounterObservation) { p[1].DiscontinuityKnown = false }},
		{"discontinuity", "counter_discontinuity_changed", func(p []CapacityCounterObservation) { p[1].DiscontinuityTicks = 12 }},
		{"restart", "uptime_wrap_or_restart_ambiguous", func(p []CapacityCounterObservation) { p[1].UptimeTicks = 200 }},
		{"elapsed mismatch", "uptime_elapsed_inconsistent", func(p []CapacityCounterObservation) { p[1].UptimeTicks++ }},
		{"overlap", "counter_poll_windows_overlap", func(p []CapacityCounterObservation) { p[0].PollCompletedAt = p[1].PollStartedAt }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, source, window, points := capacitySourceTestInput()
			if tc.name == "elapsed mismatch" {
				// Narrow bounds so one full tick is inconsistent, rather than
				// inventing a per-OID instant from a wide poll's uncertainty.
				points[0].PollCompletedAt = points[0].PollStartedAt
				points[1].PollCompletedAt = points[1].PollStartedAt
				points[1].UptimeTicks += 2
			}
			tc.change(points)
			measured, err := MeasureCapacityCounterMember(ctx, source, window, points)
			if err != nil {
				t.Fatal(err)
			}
			sample := measured.Samples("in")[0]
			if sample.Observed || sample.Reason != tc.reason || sample.BPSNumerator != "" || sample.BytesNumerator != "" || !measured.Samples("out")[0].Observed {
				t.Fatal("unknown source interval became zero or damaged independent outbound facts", sample)
			}
		})
	}
	ctx, source, window, points := capacitySourceTestInput()
	// The middle inbound poll disappears. The explicit cadence admits no
	// interpolation across the missing five-minute poll.
	points = append(points[:1], points[2:]...)
	measured, err := MeasureCapacityCounterMember(ctx, source, window, points)
	if err != nil || measured.Samples("in")[0].Observed || measured.Samples("in")[0].Reason != "counter_poll_gap" {
		t.Fatal("missing poll became a measured interval", err)
	}
}

func TestCapacityCounterSourceRefusesForeignUnorderedAndUnadmittedFacts(t *testing.T) {
	ctx, source, window, points := capacitySourceTestInput()
	foreign := tenancy.WithTenant(ctx, tenancy.ID(uuid.NewString()))
	if result, err := MeasureCapacityCounterMember(foreign, source, window, points); err == nil || !reflect.DeepEqual(result, CapacityMeasuredMember{}) {
		t.Fatal("foreign source produced a measured prefix", result, err)
	}
	points[1].PollStartedAt = points[0].PollStartedAt
	if result, err := MeasureCapacityCounterMember(ctx, source, window, points); err == nil || !reflect.DeepEqual(result, CapacityMeasuredMember{}) {
		t.Fatal("competing same-instant captures were arbitrarily selected", result, err)
	}
	ctx, source, window, points = capacitySourceTestInput()
	window.MemoryBytes = 1
	if result, err := MeasureCapacityCounterMember(ctx, source, window, points); err == nil || !reflect.DeepEqual(result, CapacityMeasuredMember{}) {
		t.Fatal("unadmitted measurement returned a prefix", result, err)
	}
}

func TestCapacityCounterSourceDoesNotGiveAReusedIndexEarlierTraffic(t *testing.T) {
	ctx, source, window, points := capacitySourceTestInput()
	source.InterfaceCreatedAt = window.From.Add(5 * time.Minute)
	member, err := MeasureCapacityCounterMember(ctx, source, window, points)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"in", "out"} {
		samples := member.Samples(direction)
		if len(samples) != 2 || samples[0].Observed || samples[0].Reason != "counter_coverage_incomplete" || samples[0].BytesNumerator != "" || !samples[1].Observed {
			t.Fatal("new canonical interface inherited earlier traffic through the same physical index", direction, samples)
		}
	}
}
