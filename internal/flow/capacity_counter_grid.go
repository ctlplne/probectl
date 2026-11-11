// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

const capacityCounterGridModel = "counter_poll_mean_overlap"

type capacityCounterGridWindow struct {
	from, to               time.Time
	maximumPollGap         time.Duration // Selected source cadence/tolerance, not an implicit fill policy.
	memoryBytes, workUnits int64
}

type capacityGridAdmission struct{ memory, work int64 }

func (b *capacityGridAdmission) debit(count, memory, work int64) bool {
	if count < 0 || memory <= 0 || work <= 0 || count > b.memory/memory || count > b.work/work {
		return false
	}
	b.memory, b.work = b.memory-count*memory, b.work-count*work
	return true
}

func (b *capacityGridAdmission) arithmetic(values ...*big.Rat) bool {
	words := int64(1)
	for _, value := range values {
		words += int64(value.Num().BitLen()/64 + value.Denom().BitLen()/64 + 2)
	}
	if words > b.work/512 || words > (b.work/512)/words {
		return false
	}
	return b.debit(words, 128, words*512)
}

func admitCapacityCounterGrid(ctx context.Context, window capacityCounterGridWindow, points []capacityCounterPoint) (int, capacityGridAdmission, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return 0, capacityGridAdmission{}, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return 0, capacityGridAdmission{}, err
	}
	span := window.to.Sub(window.from)
	if window.from.IsZero() || span <= 0 || !window.from.Add(span).Equal(window.to) || window.maximumPollGap <= 0 {
		return 0, capacityGridAdmission{}, errCapacityCounterInput
	}
	count := int64(1 + (span-1)/(5*time.Minute))
	budget := capacityGridAdmission{window.memoryBytes, window.workUnits}
	if !budget.debit(1, 8192, 8192) || !budget.debit(count, 4096, 4096) || !budget.debit(int64(len(points)), 8192, 8192) {
		return 0, capacityGridAdmission{}, errCapacityCounterInput
	}
	for i, point := range points {
		if err := ctx.Err(); err != nil {
			return 0, capacityGridAdmission{}, err
		}
		if point.tenant != tenant.String() || point.at.IsZero() || i > 0 && !point.at.After(points[i-1].at) {
			return 0, capacityGridAdmission{}, errCapacityCounterInput
		}
		for _, value := range []string{point.tenant, point.context, point.router, point.iface, point.source, point.incarnation, point.continuity} {
			if strings.TrimSpace(value) != value || !budget.debit(int64(len(value)), 32, 32) {
				return 0, capacityGridAdmission{}, errCapacityCounterInput
			}
		}
		first := points[0]
		if point.context == "" || point.router == "" || point.iface == "" || point.source == "" || point.context != first.context || point.router != first.router || point.iface != first.iface || point.source != first.source {
			return 0, capacityGridAdmission{}, errCapacityCounterInput
		}
	}
	return int(count), budget, nil
}

// capacityCounterGrid integrates each proven poll's mean rate over the exact
// overlap with a five-minute grid. This is an explicit resampling model, not an
// assertion that a poll revealed traffic's within-poll timing. Fractional octets
// survive circuit sums and percentile ranking; no integer or float rounding is
// permitted. Missing coverage, excessive poll gaps and unknown counter deltas
// invalidate the affected samples instead of becoming zeros or interpolation
// across a reset. The caller still owes current source and actor authorization.
func capacityCounterGrid(ctx context.Context, window capacityCounterGridWindow, points []capacityCounterPoint) ([]capacityCounterRate, error) {
	count, budget, err := admitCapacityCounterGrid(ctx, window, points)
	if err != nil {
		return nil, err
	}
	result := make([]capacityCounterRate, count)
	values := make([]*big.Rat, count)
	covered := make([]time.Duration, count)
	for i := range result {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start := window.from.Add(time.Duration(i) * 5 * time.Minute)
		end := start.Add(min(5*time.Minute, window.to.Sub(start)))
		result[i] = capacityCounterRate{from: start, to: end}
		values[i] = new(big.Rat)
	}
	for i := 1; i < len(points); i++ {
		before, after := points[i-1], points[i]
		if !after.at.After(window.from) || !before.at.Before(window.to) {
			continue
		}
		rate, err := capacityCounterInterval(ctx, before, after, window.memoryBytes, window.workUnits)
		if err != nil {
			return nil, err
		}
		if after.at.Sub(before.at) > window.maximumPollGap {
			rate = capacityCounterRate{from: before.at, to: after.at, reason: "counter_poll_gap"}
		}
		start, end := before.at, after.at
		if start.Before(window.from) {
			start = window.from
		}
		if end.After(window.to) {
			end = window.to
		}
		for start.Before(end) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !budget.debit(1, 128, 128) {
				return nil, errCapacityCounterInput
			}
			slot := int(start.Sub(window.from) / (5 * time.Minute))
			stop := result[slot].to
			if stop.After(end) {
				stop = end
			}
			elapsed := stop.Sub(start)
			covered[slot] += elapsed
			if !rate.observed {
				if result[slot].reason == "" {
					result[slot].reason = rate.reason
				}
			} else {
				delta, err := capacityUnsignedInteger(ctx, rate.bytes)
				if err != nil {
					return nil, err
				}
				piece := new(big.Rat).SetFrac(delta, big.NewInt(int64(after.at.Sub(before.at))))
				if !budget.arithmetic(values[slot], piece) {
					return nil, errCapacityCounterInput
				}
				piece.Mul(piece, new(big.Rat).SetInt64(int64(elapsed)))
				values[slot].Add(values[slot], piece)
				result[slot].wrapped = result[slot].wrapped || rate.wrapped
			}
			start = stop
		}
	}
	for i := range result {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sample := &result[i]
		elapsed := sample.to.Sub(sample.from)
		if covered[i] != elapsed && sample.reason == "" {
			sample.reason = "counter_coverage_incomplete"
		}
		if sample.reason != "" {
			sample.wrapped = false
			continue
		}
		if !budget.arithmetic(values[i]) {
			return nil, errCapacityCounterInput
		}
		rate := new(big.Rat).Mul(values[i], new(big.Rat).SetFrac(big.NewInt(8_000_000_000), big.NewInt(int64(elapsed))))
		sample.bytes, sample.bytesDenominator = values[i].Num().String(), values[i].Denom().String()
		sample.numerator, sample.denominator, sample.observed = rate.Num().String(), rate.Denom().String(), true
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
