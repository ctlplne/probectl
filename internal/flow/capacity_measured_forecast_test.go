// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Synthetic exact polls exercise the entire original-clock/grid/circuit/model
// path. The independent oracle operates directly on the generating bps curve;
// this is not the still-required physical SNMP or served runout acceptance.
func TestCapacityMeasuredForecastUsesWholeCounterCircuitAndHandGrowthRunout(t *testing.T) {
	ctx, source, window, _ := capacitySourceTestInput()
	const samples = 2 * 7 * 24 * 12
	window.To = window.From.Add(samples * 5 * time.Minute)
	window.MemoryBytes = 2 << 30
	work, err := CapacityForecastWorkUnits(window.MemoryBytes)
	if err != nil {
		t.Fatal(err)
	}
	window.WorkUnits = work
	source.PhysicalMaxBPS = 1_000_000_000
	var points []CapacityCounterObservation
	for _, direction := range []string{"in", "out"} {
		value := ^uint64(0) - 999
		for i := 0; i <= samples; i++ {
			at := window.From.Add(time.Duration(i) * 5 * time.Minute)
			points = append(points, CapacityCounterObservation{Direction: direction, PollStartedAt: at, PollCompletedAt: at,
				Value: value, Width: 64, UptimeTicks: 100000 + uint32(i)*30000, UptimeKnown: true, DiscontinuityKnown: true})
			// The generating mean includes the interval midpoint and a
			// weekly repeating phase. All bytes are exact integers.
			bps := uint64(8_000_000 + 800*i + 400 + 80*(i%288))
			if direction == "out" {
				bps = 4_000_000
			}
			value += bps * 300 / 8
		}
	}
	first, err := MeasureCapacityCounterMember(ctx, source, window, points)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := first.RetainedMemoryBytes(ctx)
	if err != nil || retained <= 0 || retained >= window.MemoryBytes {
		t.Fatal("complete measured grids lost their finite retained-memory charge", retained, err)
	}
	secondSource := source
	secondSource.InterfaceID = uuid.NewString()
	second, err := MeasureCapacityCounterMember(ctx, secondSource, window, points)
	if err != nil {
		t.Fatal(err)
	}
	until := window.From.Add(20 * 24 * time.Hour)
	var hand time.Time
	for i := samples; i < 20*24*12; i++ {
		if 2*(8_000_000+800*i+400+80*(i%288)) >= 24_000_000 {
			hand = window.From.Add(time.Duration(i) * 5 * time.Minute)
			break
		}
	}
	if hand.IsZero() {
		t.Fatal("independent generating curve did not reach its selected threshold")
	}
	for _, mode := range []string{"max_directional_percentiles", "interval_max", "interval_sum"} {
		t.Run(mode, func(t *testing.T) {
			threshold := uint64(24_000_000)
			if mode == "interval_sum" {
				threshold += 8_000_000 // two flat 4Mbps outbound members
			}
			got, err := ForecastCapacityMeasured(ctx, window, "owned circuit", mode, strconv.FormatUint(threshold, 10), until, []CapacityMeasuredMember{first, second})
			wantCount := 1
			if mode == "max_directional_percentiles" {
				wantCount = 2
			}
			if err != nil || len(got) != wantCount {
				t.Fatal("exact source circuit did not reach forecast model", len(got), err)
			}
			for _, forecast := range got {
				if !forecast.Trained || !forecast.CoverageComplete || forecast.ExpectedSamples != samples || forecast.ObservedSamples != samples ||
					forecast.IntervalMethod != "in_sample_residual_envelope" || forecast.CounterModel != CapacityCounterWindowModel() {
					t.Fatal("forecast changed coverage or misidentified its interval/model", forecast)
				}
				if forecast.Direction == "out" {
					if forecast.TrendNumerator != "0" || forecast.Central.Reached || forecast.Reason != "threshold_not_reached_in_horizon" {
						t.Fatal("independent flat outbound series inherited inbound growth", forecast)
					}
					continue
				}
				if forecast.TrendNumerator != "460800" || forecast.TrendDenominator != "1" {
					t.Fatal("forecast averaged member trends or rounded exact source growth", forecast)
				}
				for _, interval := range []CapacityRunoutInterval{forecast.Central, forecast.Earliest, forecast.Latest} {
					if !interval.Reached || interval.From == nil || interval.To == nil || !interval.From.Equal(hand) || !interval.To.Equal(hand.Add(5*time.Minute)) {
						t.Fatal("counter-derived runout missed the independent five-minute hand oracle", interval, hand)
					}
				}
			}
		})
	}
	points[100].UptimeKnown, points[100].UptimeTicks = false, 0
	missing, err := MeasureCapacityCounterMember(ctx, source, window, points)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ForecastCapacityMeasured(ctx, window, "owned circuit", "max_directional_percentiles", "24000000", until, []CapacityMeasuredMember{missing, second})
	if err != nil || len(got) != 2 || got[0].Trained || got[0].CoverageComplete || got[0].Reason != "training_coverage_incomplete" || got[0].ObservedSamples != samples-2 ||
		got[0].Central.Reached || !got[1].Trained || !got[1].CoverageComplete {
		t.Fatal("one missing member's original clocks shortened training or damaged the independent direction", got, err)
	}
	foreign := tenancy.WithTenant(ctx, tenancy.ID(uuid.NewString()))
	if leaked, err := ForecastCapacityMeasured(foreign, window, "owned circuit", "in", "24000000", until, []CapacityMeasuredMember{first, second}); err == nil || leaked != nil {
		t.Fatal("foreign measured members entered a forecast or returned a prefix", leaked, err)
	}
}
