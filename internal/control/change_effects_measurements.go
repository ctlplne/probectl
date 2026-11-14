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
func summarizeChangeEffectTests(ctx context.Context, tenant string, sources []store.IncidentConfiguredTest, reads []store.IncidentTestMeasurement, from, at, to time.Time, memory int64) ([]change.EffectTest, error) {
	if !from.Before(at) || !at.Before(to) || memory < 4096 {
		return nil, entity.ErrInvalidClaim
	}
	if int64(len(sources)) > memory/4096 {
		return nil, flowstore.ErrExplorerBudget
	}
	out := make([]change.EffectTest, 0, len(sources))
	selected := map[changeEffectTestKey]int{}
	totals := make([][2]changeEffectMeasurementTotals, len(sources))
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
		out = append(out, change.EffectTest{ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID, Before: period(from, at), After: period(at, to)})
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
		clock := read.ObservedAt
		preciseClock := read.Available && read.ICMP != nil && read.ICMP.Version == 3
		if preciseClock {
			clock = read.ICMP.CompletedAt
		}
		// SQL overfetches the boundary microseconds. A version3 receipt has
		// its exact original clock; older receipts cannot claim sub-microsecond
		// membership and retain a citation without contributing period values.
		ambiguousWindow := !preciseClock && (!from.Equal(from.Truncate(time.Microsecond)) && clock.Truncate(time.Microsecond).Equal(from.Truncate(time.Microsecond)) ||
			!to.Equal(to.Truncate(time.Microsecond)) && clock.Truncate(time.Microsecond).Equal(to.Truncate(time.Microsecond)))
		if (clock.Before(from) || !clock.Before(to)) && !ambiguousWindow {
			continue
		}
		if err := charge(4096 + 4*int64(len(read.Reason)+len(read.EvidenceID)+len(read.ObservationID))); err != nil {
			return nil, err
		}
		side := 0
		target := &out[index].Before
		if !clock.Before(at) {
			side = 1
			target = &out[index].After
		}
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
		complete := measurement.Attempted == measurement.Requested && measurement.Transmitted == measurement.Requested && measurement.SendErrors == 0 && measurement.ReadComplete && !measurement.IOFailed && !measurement.Canceled
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
		if measurement.Version < 3 && !at.Equal(at.Truncate(time.Microsecond)) && read.ObservedAt.Truncate(time.Microsecond).Equal(at.Truncate(time.Microsecond)) {
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
		for side, target := range []*change.EffectTestPeriod{&out[index].Before, &out[index].After} {
			tally := &totals[index][side]
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
	}
	return out, ctx.Err()
}
