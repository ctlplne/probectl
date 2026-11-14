// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func pathHealthProjectionRows() []flowstore.CounterRow {
	at := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	rows := make([]flowstore.CounterRow, 2)
	for i := range rows {
		rows[i] = flowstore.CounterRow{TenantID: "a", CounterSource: flowstore.CounterSource{ContextID: "context", DeviceID: "router", AgentID: "agent", SourceRef: "target"},
			Name: pathHealthMetricNames[0], IfIndex: 7, Value: uint64(1<<53+1) + uint64(i)*1225000, Width: 64,
			PollStartedAt: at.Add(time.Duration(i) * time.Second), PollCompletedAt: at.Add(time.Duration(i)*time.Second + 10*time.Millisecond),
			UptimeKnown: true, UptimeTicks: 10000 + uint32(i)*100, DiscontinuityKnown: true, InterfaceSpeedKnown: true, InterfaceSpeedBPS: 10000000,
			CaptureKey: [32]byte{byte(i + 1)}, RawDigest: [32]byte{byte(i + 10)}}
	}
	return rows
}

func TestPathHealthProjectsExactWordsAndHonestContinuity(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("a"))
	for _, tc := range []struct {
		name, kind, delta, reason string
		maximum                   uint64
		modify                    func([]flowstore.CounterRow)
	}{
		{"explicit bound", "exact_under_explicit_physical_bound", "1225000", "", 20000000, nil},
		{"no bound", "minimum_under_counter_continuity", "1225000", "", 0, nil},
		{"32 bit wrap", "exact_under_explicit_physical_bound", "15", "", 20000000, func(rows []flowstore.CounterRow) {
			rows[0].Width, rows[1].Width, rows[0].Value, rows[1].Value = 32, 32, 1<<32-10, 5
		}},
		{"64 bit wrap", "exact_under_explicit_physical_bound", "15", "", 20000000, func(rows []flowstore.CounterRow) { rows[0].Value, rows[1].Value = 1<<64-10, 5 }},
		{"rising word hides wraps", "minimum_under_counter_continuity", "1225000", "", 1<<64 - 1, func(rows []flowstore.CounterRow) {
			rows[0].Width, rows[1].Width, rows[0].Value, rows[1].Value = 32, 32, 10, 1225010
		}},
		{"zero is only a minimum", "minimum_under_counter_continuity", "0", "", 0, func(rows []flowstore.CounterRow) { rows[1].Value = rows[0].Value }},
		{"bound contradicted", "unavailable", "", "counter_exceeds_explicit_physical_bound", 1, nil},
		{"reset", "unavailable", "", "counter_discontinuity", 0, func(rows []flowstore.CounterRow) { rows[1].DiscontinuityTicks = 1 }},
		{"missing clock", "unavailable", "", "counter_clock_unavailable", 0, func(rows []flowstore.CounterRow) { rows[0].UptimeKnown = false }},
		{"restart", "unavailable", "", "uptime_or_source_restart", 0, func(rows []flowstore.CounterRow) { rows[1].UptimeTicks = 0 }},
		{"overlap", "unavailable", "", "overlapping_or_unordered_polls", 0, func(rows []flowstore.CounterRow) {
			rows[0].PollCompletedAt = rows[1].PollStartedAt.Add(time.Millisecond)
		}},
		{"width change", "unavailable", "", "counter_width_changed", 0, func(rows []flowstore.CounterRow) { rows[0].Width, rows[0].Value = 32, 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := pathHealthProjectionRows()
			if tc.modify != nil {
				tc.modify(rows)
			}
			out, err := projectPathHealth(ctx, rows, rows[1].PollCompletedAt, 5*time.Minute, tc.maximum)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 6 || out[0].RateKind != tc.kind || out[0].MinimumDelta != tc.delta || out[0].Reason != tc.reason {
				t.Fatalf("original counters changed or unsupported rate asserted: %+v", out)
			}
			if out[0].Value == "" || out[0].PreviousValue == "" || out[0].CaptureKey == out[0].PreviousCaptureKey || out[1].Reason != "no_original_observation" {
				t.Fatal("original receipt or explicit missing direction omitted")
			}
			if tc.name == "explicit bound" && (out[0].PreviousValue != "9007199254740993" || out[0].RateNumerator != "9800000" || out[0].RateDenominator != "1" || out[0].UtilizationNumerator != "98" || out[0].UtilizationDenominator != "1" || out[0].UtilizationKind != "exact_under_explicit_physical_bound_and_constant_polled_speed") {
				t.Fatalf("exact original words or independent hand utilization changed: %+v", out[0])
			}
		})
	}
}

func TestPathHealthRefusesAmbiguousMissingAndForeignRows(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("a"))
	base := pathHealthProjectionRows()
	for _, rows := range [][]flowstore.CounterRow{
		{base[0], base[0], base[1]}, {base[1], base[0], base[0]}, {base[0], base[1], base[1]},
	} {
		out, err := projectPathHealth(ctx, rows, base[1].PollCompletedAt, time.Minute, 20000000)
		if err != nil || out[0].Reason != "ambiguous_poll_clock" || out[0].RateNumerator != "" {
			t.Fatal("duplicate original poll asserted a rate", out, err)
		}
	}
	for _, known := range []bool{false, true} {
		rows := pathHealthProjectionRows()
		rows[1].InterfaceSpeedKnown, rows[1].InterfaceSpeedBPS = known, 0
		out, err := projectPathHealth(ctx, rows, base[1].PollCompletedAt, time.Minute, 20000000)
		if err != nil || out[0].UtilizationNumerator != "" || out[0].RateNumerator != "9800000" {
			t.Fatal("unknown or zero speed became utilization", out, err)
		}
	}
	for _, tc := range []struct {
		rows   []flowstore.CounterRow
		to     time.Time
		reason string
	}{
		{base[:1], base[1].PollCompletedAt, "one_original_poll"},
		{base, base[1].PollCompletedAt.Add(2 * time.Minute), "missing_or_stale_poll"},
	} {
		out, err := projectPathHealth(ctx, tc.rows, tc.to, time.Minute, 0)
		if err != nil || out[0].Reason != tc.reason || out[0].RateNumerator != "" {
			t.Fatal("incomplete history became a rate", out, err)
		}
	}
	for _, alter := range []func([]flowstore.CounterRow){
		func(rows []flowstore.CounterRow) { rows[1].TenantID = "b" },
		func(rows []flowstore.CounterRow) { rows[1].DeviceID = "sibling-router" },
		func(rows []flowstore.CounterRow) { rows[1].SourceAssignedAt = time.Now() },
		func(rows []flowstore.CounterRow) { rows[1].InterfaceSpeedKnown = false },
	} {
		rows := pathHealthProjectionRows()
		alter(rows)
		if _, err := projectPathHealth(ctx, rows, base[1].PollCompletedAt, time.Minute, 0); !errors.Is(err, flowstore.ErrCounterHistoryInput) {
			t.Fatal("foreign or invalid original evidence accepted", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := projectPathHealth(canceled, base, base[1].PollCompletedAt, time.Minute, 0); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled history accepted", err)
	}
}
