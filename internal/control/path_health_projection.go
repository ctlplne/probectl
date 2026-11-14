// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"math/big"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type pathHealthCounter struct {
	Metric                  string     `json:"metric"`
	Value                   string     `json:"value,omitempty"`
	PreviousValue           string     `json:"previous_value,omitempty"`
	PollStartedAt           *time.Time `json:"poll_started_at,omitempty"`
	PollCompletedAt         *time.Time `json:"poll_completed_at,omitempty"`
	PreviousPollStartedAt   *time.Time `json:"previous_poll_started_at,omitempty"`
	PreviousPollCompletedAt *time.Time `json:"previous_poll_completed_at,omitempty"`
	CaptureKey              string     `json:"capture_key,omitempty"`
	PreviousCaptureKey      string     `json:"previous_capture_key,omitempty"`
	RawDigest               string     `json:"raw_digest,omitempty"`
	PreviousRawDigest       string     `json:"previous_raw_digest,omitempty"`
	Width                   uint32     `json:"counter_width,omitempty"`
	SpeedBPS                string     `json:"interface_speed_bps,omitempty"`
	PreviousSpeedBPS        string     `json:"previous_interface_speed_bps,omitempty"`
	MinimumDelta            string     `json:"minimum_delta,omitempty"`
	RateNumerator           string     `json:"rate_numerator,omitempty"`
	RateDenominator         string     `json:"rate_denominator,omitempty"`
	RateKind                string     `json:"rate_kind"`
	RateUnit                string     `json:"rate_unit"`
	UtilizationNumerator    string     `json:"utilization_numerator,omitempty"`
	UtilizationDenominator  string     `json:"utilization_denominator,omitempty"`
	UtilizationKind         string     `json:"utilization_kind,omitempty"`
	Reason                  string     `json:"reason,omitempty"`
}

var pathHealthMetricNames = []string{
	"probectl.device.if.in.octets", "probectl.device.if.out.octets",
	"probectl.device.if.in.errors", "probectl.device.if.out.errors",
	"probectl.device.if.in.discards", "probectl.device.if.out.discards",
	"probectl.device.if.in.fcs.errors", "probectl.device.if.in.alignment.errors",
}

type pathHealthPair struct {
	previous, latest                   *flowstore.CounterRow
	latestAmbiguous, previousAmbiguous bool
}

// This projection consumes already authorized original rows, never a public
// claim of continuity. A modular delta without an independent upper bound is
// only a minimum; even a rising counter can hide one or more complete wraps.
func projectPathHealth(ctx context.Context, rows []flowstore.CounterRow, to time.Time, gap time.Duration, physicalMax uint64) ([]pathHealthCounter, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || gap <= 0 || to.IsZero() {
		return nil, flowstore.ErrCounterHistoryInput
	}
	pairs := make(map[string]pathHealthPair, len(pathHealthMetricNames))
	for _, name := range pathHealthMetricNames {
		pairs[name] = pathHealthPair{}
	}
	for i := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := &rows[i]
		base := &rows[0]
		if row.ContextID != base.ContextID || row.DeviceID != base.DeviceID || row.AgentID != base.AgentID || row.SourceRef != base.SourceRef || row.IfIndex != base.IfIndex || !row.SourceAssignedAt.Equal(base.SourceAssignedAt) || !row.AgentAssignedAt.Equal(base.AgentAssignedAt) {
			return nil, flowstore.ErrCounterHistoryInput
		}
		pair, known := pairs[row.Name]
		if !known || row.TenantID != tenant.String() || row.PollStartedAt.IsZero() || row.PollCompletedAt.Before(row.PollStartedAt) ||
			(row.Width != 32 && row.Width != 64) || row.Width == 32 && row.Value > 1<<32-1 ||
			!row.InterfaceSpeedKnown && row.InterfaceSpeedBPS != 0 {
			return nil, flowstore.ErrCounterHistoryInput
		}
		switch {
		case pair.latest == nil || row.PollStartedAt.After(pair.latest.PollStartedAt):
			pair.previous, pair.previousAmbiguous = pair.latest, pair.latestAmbiguous
			pair.latest, pair.latestAmbiguous = row, false
		case row.PollStartedAt.Equal(pair.latest.PollStartedAt):
			pair.latestAmbiguous = true
		case pair.previous == nil || row.PollStartedAt.After(pair.previous.PollStartedAt):
			pair.previous, pair.previousAmbiguous = row, false
		case row.PollStartedAt.Equal(pair.previous.PollStartedAt):
			pair.previousAmbiguous = true
		}
		pairs[row.Name] = pair
	}
	result := make([]pathHealthCounter, 0, len(pathHealthMetricNames))
	for _, name := range pathHealthMetricNames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result = append(result, projectPathHealthPair(name, pairs[name], to, gap, physicalMax))
	}
	return result, nil
}

func projectPathHealthPair(name string, pair pathHealthPair, to time.Time, gap time.Duration, physicalMax uint64) pathHealthCounter {
	out := pathHealthCounter{Metric: name, RateKind: "unavailable", RateUnit: "packets/s", Reason: "no_original_observation"}
	octets := name == pathHealthMetricNames[0] || name == pathHealthMetricNames[1]
	if octets {
		out.RateUnit = "bits/s"
	}
	a, b := pair.previous, pair.latest
	if b == nil {
		return out
	}
	out.Value, out.Width = strconv.FormatUint(b.Value, 10), b.Width
	out.PollStartedAt, out.PollCompletedAt = pathHealthTime(b.PollStartedAt), pathHealthTime(b.PollCompletedAt)
	out.CaptureKey, out.RawDigest = hex.EncodeToString(b.CaptureKey[:]), hex.EncodeToString(b.RawDigest[:])
	if b.InterfaceSpeedKnown {
		out.SpeedBPS = strconv.FormatUint(b.InterfaceSpeedBPS, 10)
	}
	if a == nil {
		out.Reason = "one_original_poll"
		return out
	}
	out.PreviousValue = strconv.FormatUint(a.Value, 10)
	out.PreviousPollStartedAt, out.PreviousPollCompletedAt = pathHealthTime(a.PollStartedAt), pathHealthTime(a.PollCompletedAt)
	out.PreviousCaptureKey, out.PreviousRawDigest = hex.EncodeToString(a.CaptureKey[:]), hex.EncodeToString(a.RawDigest[:])
	if a.InterfaceSpeedKnown {
		out.PreviousSpeedBPS = strconv.FormatUint(a.InterfaceSpeedBPS, 10)
	}
	if reason := pathHealthContinuity(a, b, to, gap); reason != "" {
		out.Reason = reason
		return out
	}
	if pair.latestAmbiguous || pair.previousAmbiguous {
		out.Reason = "ambiguous_poll_clock"
		return out
	}
	elapsed := b.PollStartedAt.Sub(a.PollStartedAt)
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(b.Width))
	delta := new(big.Int).Sub(new(big.Int).SetUint64(b.Value), new(big.Int).SetUint64(a.Value))
	if delta.Sign() < 0 {
		delta.Add(delta, modulus)
	}
	out.RateKind = "minimum_under_counter_continuity"
	if octets && physicalMax != 0 {
		maximum := new(big.Int).Mul(new(big.Int).SetUint64(physicalMax), big.NewInt(int64(elapsed)))
		maximum.Quo(maximum, big.NewInt(8_000_000_000))
		if delta.Cmp(maximum) > 0 {
			out.RateKind, out.Reason = "unavailable", "counter_exceeds_explicit_physical_bound"
			return out
		}
		if new(big.Int).Add(new(big.Int).Set(delta), modulus).Cmp(maximum) > 0 {
			out.RateKind = "exact_under_explicit_physical_bound"
		}
	}
	out.MinimumDelta, out.Reason = delta.String(), ""
	scale := int64(1_000_000_000)
	if octets {
		scale *= 8
	}
	rate := new(big.Rat).SetFrac(new(big.Int).Mul(new(big.Int).Set(delta), big.NewInt(scale)), big.NewInt(int64(elapsed)))
	out.RateNumerator, out.RateDenominator = rate.Num().String(), rate.Denom().String()
	if octets && a.InterfaceSpeedKnown && b.InterfaceSpeedKnown && a.InterfaceSpeedBPS != 0 && a.InterfaceSpeedBPS == b.InterfaceSpeedBPS {
		percent := new(big.Rat).Mul(rate, big.NewRat(100, 1))
		percent.Quo(percent, new(big.Rat).SetInt(new(big.Int).SetUint64(b.InterfaceSpeedBPS)))
		out.UtilizationNumerator, out.UtilizationDenominator = percent.Num().String(), percent.Denom().String()
		out.UtilizationKind = out.RateKind + "_and_constant_polled_speed"
	}
	return out
}

func pathHealthContinuity(a, b *flowstore.CounterRow, to time.Time, gap time.Duration) string {
	if !b.PollStartedAt.After(a.PollStartedAt) || a.PollCompletedAt.After(b.PollStartedAt) {
		return "overlapping_or_unordered_polls"
	}
	if b.PollCompletedAt.After(to) || to.Sub(b.PollCompletedAt) > gap || b.PollStartedAt.Sub(a.PollStartedAt) > gap {
		return "missing_or_stale_poll"
	}
	if a.Width != b.Width {
		return "counter_width_changed"
	}
	if !a.UptimeKnown || !b.UptimeKnown || !a.DiscontinuityKnown || !b.DiscontinuityKnown {
		return "counter_clock_unavailable"
	}
	if a.DiscontinuityTicks != b.DiscontinuityTicks {
		return "counter_discontinuity"
	}
	elapsed := b.PollStartedAt.Sub(a.PollStartedAt)
	const uptimeModulus = time.Duration(1<<32) * 10 * time.Millisecond
	if elapsed >= uptimeModulus {
		return "uptime_wrap_ambiguous"
	}
	uptime := time.Duration(b.UptimeTicks-a.UptimeTicks) * 10 * time.Millisecond
	tolerance := a.PollCompletedAt.Sub(a.PollStartedAt) + b.PollCompletedAt.Sub(b.PollStartedAt) + 20*time.Millisecond
	if uptime < elapsed-tolerance || uptime > elapsed+tolerance {
		return "uptime_or_source_restart"
	}
	return ""
}

func pathHealthTime(at time.Time) *time.Time { return &at }
