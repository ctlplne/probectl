// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// CapacityCounterSource is current canonical inventory selected by the storage
// reader. It is not an authority token. PhysicalMaxBPS is the operator's explicit
// upper bound for the entire historical window, never a commit or current speed
// silently applied to old observations.
type CapacityCounterSource struct {
	TenantID, ContextID, DeviceID, InterfaceID string
	AgentID, SourceRef                         string
	SourceAssignedAt, AgentAssignedAt          time.Time
	PhysicalMaxBPS                             uint64
}

type CapacityMeasurementWindow struct {
	From, To               time.Time
	MaximumPollGap         time.Duration
	MemoryBytes, WorkUnits int64
}

// CapacityCounterObservation carries exact retained facts after the reader has
// verified original capture receipts. No caller-provided continuity/boot label
// can turn an ambiguous interval into measured traffic.
type CapacityCounterObservation struct {
	Direction                       string
	PollStartedAt, PollCompletedAt  time.Time
	Value                           uint64
	Width                           uint8
	UptimeTicks, DiscontinuityTicks uint32
	UptimeKnown, DiscontinuityKnown bool
}

type CapacityCounterSample struct {
	From             time.Time `json:"from"`
	To               time.Time `json:"to"`
	BytesNumerator   string    `json:"bytes_numerator,omitempty"`
	BytesDenominator string    `json:"bytes_denominator,omitempty"`
	BPSNumerator     string    `json:"bps_numerator,omitempty"`
	BPSDenominator   string    `json:"bps_denominator,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	Observed         bool      `json:"observed"`
	Wrapped          bool      `json:"wrapped"`
}

// CapacityMeasuredMember keeps private exact grids, so later billing/forecast
// operations cannot accept public JSON claiming to be a measured member.
type CapacityMeasuredMember struct {
	source  CapacityCounterSource
	in, out []capacityCounterRate
}

func (m CapacityMeasuredMember) Source() CapacityCounterSource { return m.source }

func capacitySample(rate capacityCounterRate) CapacityCounterSample {
	denominator := rate.bytesDenominator
	if rate.observed && denominator == "" {
		denominator = "1"
	}
	return CapacityCounterSample{From: rate.from, To: rate.to, BytesNumerator: rate.bytes,
		BytesDenominator: denominator, BPSNumerator: rate.numerator, BPSDenominator: rate.denominator,
		Reason: rate.reason, Observed: rate.observed, Wrapped: rate.wrapped}
}

func (m CapacityMeasuredMember) Samples(direction string) []CapacityCounterSample {
	var rates []capacityCounterRate
	switch direction {
	case "in":
		rates = m.in
	case "out":
		rates = m.out
	default:
		return nil
	}
	result := make([]CapacityCounterSample, len(rates))
	for i, rate := range rates {
		result[i] = capacitySample(rate)
	}
	return result
}

// MeasureCapacityCounterMember uses an explicit poll-start/mean-overlap model.
// SNMP does not attest a per-OID read instant: poll bounds are retained, and
// uptime consistency is checked against their entire uncertainty interval.
// Rates are exact within this stated resampling model, not claims about traffic
// timing inside a poll. The storage reader still owes current actor, source and
// original-receipt revalidation before publishing the result.
func MeasureCapacityCounterMember(ctx context.Context, source CapacityCounterSource, window CapacityMeasurementWindow, observations []CapacityCounterObservation) (CapacityMeasuredMember, error) {
	none := CapacityMeasuredMember{}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != source.TenantID {
		return none, tenancy.ErrNoTenant
	}
	if !capacityAgreementUUID(source.TenantID) || !capacityAgreementUUID(source.ContextID) || !capacityAgreementUUID(source.DeviceID) || !capacityAgreementUUID(source.InterfaceID) ||
		!capacityAgreementText(source.AgentID, true) || !capacityAgreementText(source.SourceRef, true) || source.SourceAssignedAt.IsZero() || source.AgentAssignedAt.IsZero() {
		return none, errCapacityCounterInput
	}
	admission := capacityGridAdmission{window.MemoryBytes / 4, window.WorkUnits / 4}
	if !admission.debit(int64(len(observations)), 8192, 8192) {
		return none, errCapacityCounterInput
	}
	for _, value := range []string{source.TenantID, source.ContextID, source.DeviceID, source.InterfaceID, source.AgentID, source.SourceRef} {
		if !admission.debit(int64(len(value)), 64, 64) {
			return none, errCapacityCounterInput
		}
	}
	incarnation := source.SourceAssignedAt.Format(time.RFC3339Nano) + "/" + source.AgentAssignedAt.Format(time.RFC3339Nano)
	in, out := []capacityCounterPoint{}, []capacityCounterPoint{}
	previous := map[string]CapacityCounterObservation{}
	for _, observation := range observations {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if err := validateCapacityCounterObservation(source, observation); err != nil {
			return none, err
		}
		point := capacityCounterPoint{tenant: source.TenantID, context: source.ContextID, router: source.DeviceID, iface: source.InterfaceID,
			source: source.AgentID + "/" + source.SourceRef, incarnation: incarnation, continuity: "original_poll_clocks",
			at: observation.PollStartedAt, exact: true, width: observation.Width, octets: observation.Value, maxBitsPerSecond: source.PhysicalMaxBPS}
		if before, present := previous[observation.Direction]; present {
			if !observation.PollStartedAt.After(before.PollStartedAt) {
				return none, errCapacityCounterInput // competing captures at one instant are not arbitrarily selected
			}
			point.intervalReason = capacityPollContinuity(before, observation)
		}
		previous[observation.Direction] = observation
		if observation.Direction == "in" {
			in = append(in, point)
		} else {
			out = append(out, point)
		}
	}
	gridWindow := capacityCounterGridWindow{from: window.From, to: window.To, maximumPollGap: window.MaximumPollGap, memoryBytes: window.MemoryBytes / 4, workUnits: window.WorkUnits / 4}
	inRates, err := capacityCounterGrid(ctx, gridWindow, in)
	if err != nil {
		return none, err
	}
	outRates, err := capacityCounterGrid(ctx, gridWindow, out)
	if err != nil {
		return none, err
	}
	return CapacityMeasuredMember{source: source, in: inRates, out: outRates}, nil
}

func validateCapacityCounterObservation(source CapacityCounterSource, point CapacityCounterObservation) error {
	if point.Direction != "in" && point.Direction != "out" || point.PollStartedAt.IsZero() || point.PollCompletedAt.Before(point.PollStartedAt) ||
		point.PollStartedAt.Before(source.SourceAssignedAt) || point.PollStartedAt.Before(source.AgentAssignedAt) ||
		(point.Width != 32 && point.Width != 64) || point.Width == 32 && point.Value > 1<<32-1 ||
		!point.UptimeKnown && point.UptimeTicks != 0 || !point.DiscontinuityKnown && point.DiscontinuityTicks != 0 {
		return errCapacityCounterInput
	}
	return nil
}

func capacityPollContinuity(before, after CapacityCounterObservation) string {
	if !before.UptimeKnown || !after.UptimeKnown || !before.DiscontinuityKnown || !after.DiscontinuityKnown {
		return "uptime_or_discontinuity_unavailable"
	}
	if after.DiscontinuityTicks != before.DiscontinuityTicks {
		return "counter_discontinuity_changed"
	}
	if !after.PollStartedAt.After(before.PollCompletedAt) {
		return "counter_poll_windows_overlap"
	}
	if after.UptimeTicks < before.UptimeTicks {
		return "uptime_wrap_or_restart_ambiguous"
	}
	minimum := after.PollStartedAt.Sub(before.PollCompletedAt) - 10*time.Millisecond
	span := after.PollCompletedAt.Sub(before.PollStartedAt)
	if span <= 0 || span > time.Duration(1<<63-1)-10*time.Millisecond || !before.PollStartedAt.Add(span).Equal(after.PollCompletedAt) {
		return "uptime_interval_unrepresentable"
	}
	maximum := span + 10*time.Millisecond
	delta := time.Duration(uint64(after.UptimeTicks)-uint64(before.UptimeTicks)) * 10 * time.Millisecond
	if delta < minimum || delta > maximum {
		return "uptime_elapsed_inconsistent"
	}
	// Even matching deltas are insufficient near a restart: a post-restart
	// uptime that fits wholly between these polls cannot prove continuity.
	if time.Duration(after.UptimeTicks)*10*time.Millisecond <= maximum {
		return "uptime_restart_ambiguous"
	}
	return ""
}

// CapacityCounterWindowModel names the nominal clock and integration convention
// that every public result must display alongside coverage and unknown reasons.
func CapacityCounterWindowModel() string { return "poll_start_" + capacityCounterGridModel }
