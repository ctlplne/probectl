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

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type changeEffectTestKey struct{ context, entity, test, agent string }

type changeEffectMeasurementTotals struct {
	sent, replied, lost, sum, count big.Int
	minimum, maximum                uint64
	observedRTT, legacyRTT          int
}

// The caller owns original-source/current-credential publication. This pure
// complete projection cannot supply access, invent missing samples or allocate
// an incomplete execution across a change boundary.
type originalMeasurementWindow struct{ from, to time.Time }

type originalTestPeriods struct {
	source  store.IncidentConfiguredTest
	periods []change.EffectTestPeriod
}

func summarizeChangeEffectTests(ctx context.Context, tenant string, sources []store.IncidentConfiguredTest, reads []store.IncidentTestMeasurement, from, at, to time.Time, memory int64) ([]change.EffectTest, error) {
	periods, err := summarizeOriginalTestPeriods(ctx, tenant, sources, reads, []originalMeasurementWindow{{from, at}, {at, to}}, memory)
	if err != nil {
		return nil, err
	}
	out := make([]change.EffectTest, 0, len(periods))
	for _, test := range periods {
		source := test.source
		out = append(out, change.EffectTest{ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID, Before: test.periods[0], After: test.periods[1]})
	}
	return out, nil
}

// A carrier window and a before/after comparison share the same complete
// original observation projection. No synthetic change boundary is introduced
// when only one selected window is requested.
func summarizeOriginalTestPeriods(ctx context.Context, tenant string, sources []store.IncidentConfiguredTest, reads []store.IncidentTestMeasurement, windows []originalMeasurementWindow, memory int64) ([]originalTestPeriods, error) {
	if len(windows) == 0 || memory < 4096 {
		return nil, entity.ErrInvalidClaim
	}
	for i, window := range windows {
		if !window.from.Before(window.to) || i > 0 && !windows[i-1].to.Equal(window.from) {
			return nil, entity.ErrInvalidClaim
		}
	}
	from, to := windows[0].from, windows[len(windows)-1].to
	if int64(len(sources)) > memory/4096 {
		return nil, flowstore.ErrExplorerBudget
	}
	out := make([]originalTestPeriods, 0, len(sources))
	selected := map[changeEffectTestKey]int{}
	totals := make([][]changeEffectMeasurementTotals, len(sources))
	charge := func(cost int64) error {
		if cost < 0 || cost > memory {
			return flowstore.ErrExplorerBudget
		}
		memory -= cost
		return ctx.Err()
	}
	period := func(start, end time.Time) change.EffectTestPeriod {
		return change.EffectTestPeriod{From: start, To: end, Observations: []change.EffectTestObservation{}, LossCoverage: "no_retained_observations", LatencyCoverage: "no_retained_observations"}
	}
	for _, source := range sources {
		if source.TenantID != tenant {
			return nil, entity.ErrScopeMismatch
		}
		if err := charge(4096 + 4*int64(len(source.AgentID))); err != nil {
			return nil, err
		}
		key := changeEffectTestKey{source.ContextID, source.EntityID, source.TestID, source.AgentID}
		if _, exists := selected[key]; exists {
			return nil, entity.ErrConflictingEvidence
		}
		selected[key] = len(out)
		if int64(len(windows)) > memory/512 {
			return nil, flowstore.ErrExplorerBudget
		}
		if err := charge(int64(len(windows)) * 512); err != nil {
			return nil, err
		}
		test := originalTestPeriods{source: source, periods: make([]change.EffectTestPeriod, 0, len(windows))}
		for _, window := range windows {
			test.periods = append(test.periods, period(window.from, window.to))
		}
		totals[len(out)] = make([]changeEffectMeasurementTotals, len(windows))
		out = append(out, test)
	}
	one := big.NewInt(1)
	seen := map[string]bool{}
	for _, read := range reads {
		if read.TenantID != tenant {
			return nil, entity.ErrScopeMismatch
		}
		index, ok := selected[changeEffectTestKey{read.ContextID, read.EntityID, read.TestID, read.AgentID}]
		if !ok || read.EvidenceID == "" || read.ObservationID == "" || seen[read.EvidenceID] || read.CaptureDigest == ([32]byte{}) {
			return nil, entity.ErrConflictingEvidence
		}
		seen[read.EvidenceID] = true
		clock, ambiguousWindow, inWindow := changeEffectObservationClock(read, from, to)
		if !inWindow {
			continue
		}
		if err := charge(4096 + 4*int64(len(read.Reason)+len(read.EvidenceID)+len(read.ObservationID))); err != nil {
			return nil, err
		}
		side := 0
		ambiguousSplit := false
		for boundary := 1; boundary < len(windows); boundary++ {
			at := windows[boundary].from
			if !clock.Before(at) {
				side = boundary
			}
			if read.ICMP != nil && read.ICMP.Version < 3 && !at.Equal(at.Truncate(time.Microsecond)) && read.ObservedAt.Truncate(time.Microsecond).Equal(at.Truncate(time.Microsecond)) {
				ambiguousSplit = true
			}
		}
		target := &out[index].periods[side]
		tally := &totals[index][side]
		observation := change.EffectTestObservation{EvidenceID: read.EvidenceID, ObservationID: read.ObservationID, CaptureDigest: hex.EncodeToString(read.CaptureDigest[:]), ObservedAt: clock, Reason: read.Reason}
		measurement := read.ICMP
		if !read.Available || measurement == nil {
			if observation.Reason == "" {
				observation.Reason = "unavailable_original_icmp_observation"
			}
			target.UnavailableExecutions++
			tally.legacyRTT++
			target.Observations = append(target.Observations, observation)
			continue
		}
		if measurement.Requested == 0 || measurement.Replies > measurement.Transmitted || measurement.Transmitted > measurement.Attempted || measurement.Attempted > measurement.Requested {
			return nil, entity.ErrInvalidClaim
		}
		if measurement.Version == 3 && (measurement.RoundTrips == nil || uint64(len(measurement.RoundTrips.Nanos)) != uint64(measurement.Replies)) {
			return nil, entity.ErrInvalidClaim
		}
		observation.Available = true
		observation.Packets = &change.EffectPackets{Transmitted: strconv.FormatUint(uint64(measurement.Transmitted), 10), Replies: strconv.FormatUint(uint64(measurement.Replies), 10)}
		complete := completeChangeEffectExecution(measurement)
		if complete {
			observation.Packets.Lost = strconv.FormatUint(uint64(measurement.Transmitted-measurement.Replies), 10)
		}
		originalRTT := measurement.RoundTrips
		if originalRTT != nil {
			if int64(len(originalRTT.Nanos)) > memory/128 {
				return nil, flowstore.ErrExplorerBudget
			}
			if err := charge(int64(len(originalRTT.Nanos))*128 + 1024); err != nil {
				return nil, err
			}
			observation.RoundTrips = &change.EffectOriginalRoundTrips{Nanos: make([]string, len(originalRTT.Nanos)), ExecutionNanos: strconv.FormatUint(originalRTT.ExecutionNanos, 10)}
			for i, value := range originalRTT.Nanos {
				observation.RoundTrips.Nanos[i] = strconv.FormatUint(value, 10)
			}
		}
		// A result that straddles the selected interval/change retains its exact
		// citation but cannot assign its packet population or RTTs to either side.
		if ambiguousWindow {
			observation.Reason = "ambiguous_quantized_window_boundary"
			target.UnavailableExecutions++
			tally.legacyRTT++
			target.Observations = append(target.Observations, observation)
			continue
		}
		if ambiguousSplit {
			observation.Reason = "ambiguous_quantized_change_boundary"
			target.UnavailableExecutions++
			tally.legacyRTT++
			target.Observations = append(target.Observations, observation)
			continue
		}
		if measurement.StartedAt.Before(target.From) || measurement.CompletedAt.After(target.To) {
			observation.Reason = "execution_straddles_comparison_boundary"
			target.UnavailableExecutions++
			tally.legacyRTT++
			target.Observations = append(target.Observations, observation)
			continue
		}
		if complete {
			target.CompleteExecutions++
			var value big.Int
			value.SetUint64(uint64(measurement.Transmitted))
			tally.sent.Add(&tally.sent, &value)
			value.SetUint64(uint64(measurement.Replies))
			tally.replied.Add(&tally.replied, &value)
			value.SetUint64(uint64(measurement.Transmitted - measurement.Replies))
			tally.lost.Add(&tally.lost, &value)
		} else {
			target.UnavailableExecutions++
		}
		if originalRTT == nil {
			tally.legacyRTT++
		} else {
			tally.observedRTT++
			for _, value := range originalRTT.Nanos {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if tally.count.Sign() == 0 || value < tally.minimum {
					tally.minimum = value
				}
				if value > tally.maximum {
					tally.maximum = value
				}
				var original big.Int
				original.SetUint64(value)
				tally.sum.Add(&tally.sum, &original)
				tally.count.Add(&tally.count, one)
			}
		}
		target.Observations = append(target.Observations, observation)
	}
	for index := range out {
		for side := range out[index].periods {
			finishChangeEffectPeriod(&out[index].periods[side], &totals[index][side])
		}
	}
	return out, ctx.Err()
}

// The exact original clock is independent of its quantized PostgreSQL index.
// Boundary-bucket legacy receipts retain their citation without inventing time.
func changeEffectObservationClock(read store.IncidentTestMeasurement, from, to time.Time) (time.Time, bool, bool) {
	clock := read.ObservedAt
	precise := read.Available && read.ICMP != nil && read.ICMP.Version == 3
	if precise {
		clock = read.ICMP.CompletedAt
	}
	ambiguous := !precise && (!from.Equal(from.Truncate(time.Microsecond)) && clock.Truncate(time.Microsecond).Equal(from.Truncate(time.Microsecond)) ||
		!to.Equal(to.Truncate(time.Microsecond)) && clock.Truncate(time.Microsecond).Equal(to.Truncate(time.Microsecond)))
	return clock, ambiguous, ambiguous || (!clock.Before(from) && clock.Before(to))
}

func finishChangeEffectPeriod(target *change.EffectTestPeriod, tally *changeEffectMeasurementTotals) {
	if target.CompleteExecutions > 0 {
		target.Packets = &change.EffectPackets{Transmitted: tally.sent.String(), Replies: tally.replied.String(), Lost: tally.lost.String()}
		target.LossCoverage = "observed_complete_executions_only"
		if tally.sent.Sign() > 0 {
			value := new(big.Rat).SetFrac(&tally.lost, &tally.sent).RatString()
			target.LossRatio = &value
		}
	} else if len(target.Observations) > 0 {
		target.LossCoverage = "unavailable_complete_packet_population"
	}
	if target.UnavailableExecutions > 0 && target.CompleteExecutions > 0 {
		target.LossCoverage = "partial_observed_execution_coverage"
	}
	switch {
	case tally.count.Sign() > 0:
		target.Latency = &change.EffectLatency{Samples: tally.count.String(), SumNanos: tally.sum.String(), MinimumNanos: strconv.FormatUint(tally.minimum, 10), MaximumNanos: strconv.FormatUint(tally.maximum, 10), MeanNanos: new(big.Rat).SetFrac(&tally.sum, &tally.count).RatString(), TimingSource: "application_monotonic"}
		target.LatencyCoverage = "observed_original_round_trips_only"
		if tally.legacyRTT > 0 {
			target.LatencyCoverage = "partial_original_round_trip_coverage"
		}
	case tally.observedRTT > 0:
		target.LatencyCoverage = "no_successful_replies"
	case len(target.Observations) > 0:
		target.LatencyCoverage = "unavailable_original_round_trips"
	}
}

func completeChangeEffectExecution(m *entity.ICMPMeasurement) bool {
	return m != nil && m.Requested > 0 && m.Attempted == m.Requested && m.Transmitted == m.Requested &&
		m.SendErrors == 0 && m.ReadComplete && !m.IOFailed && !m.Canceled
}
