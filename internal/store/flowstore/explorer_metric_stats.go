// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"math/big"
	"sort"
	"time"
)

// metricBucket is an observed nonempty time bucket. Absent buckets are zero
// observations, not missing samples. Rate averages use actual bucket duration.
type metricBucket struct {
	value    *big.Rat
	duration time.Duration
}

// calculateFlowMetric is the exact reference for the D102 statistical plan.
// p95/p99 use weighted nearest rank, including unobserved zero buckets without
// allocating one entry per minute of a long retention range. Distinct totals
// must be supplied from actual whole-window identities, never bucket sums.
func calculateFlowMetric(input []metricBucket, bucketCount uint64, window time.Duration, calculation string, total *big.Rat, rate bool) (*big.Rat, error) {
	if bucketCount == 0 || uint64(len(input)) > bucketCount || window <= 0 {
		return nil, errors.New("invalid flow metric sample bounds")
	}
	samples := make([]metricBucket, len(input))
	weighted := new(big.Rat)
	sum := new(big.Rat)
	maximum := new(big.Rat)
	var observedDuration time.Duration
	for i, item := range input {
		if item.value == nil || item.value.Sign() < 0 || item.duration <= 0 || item.duration > window {
			return nil, errors.New("invalid flow metric sample")
		}
		if observedDuration > window-item.duration {
			return nil, errors.New("flow sample durations exceed the query window")
		}
		observedDuration += item.duration
		samples[i] = metricBucket{value: new(big.Rat).Set(item.value), duration: item.duration}
		sum.Add(sum, item.value)
		weighted.Add(weighted, new(big.Rat).Mul(item.value, new(big.Rat).SetInt64(int64(item.duration))))
		if item.value.Cmp(maximum) > 0 {
			maximum.Set(item.value)
		}
	}
	switch calculation {
	case "bucket_total":
		return sum, nil
	case "total":
		if total == nil || total.Sign() < 0 {
			return nil, errors.New("flow total requires its underlying aggregate")
		}
		return new(big.Rat).Set(total), nil
	case "avg":
		if rate {
			return weighted.Quo(weighted, new(big.Rat).SetInt64(int64(window))), nil
		}
		return sum.Quo(sum, new(big.Rat).SetInt(new(big.Int).SetUint64(bucketCount))), nil
	case "max":
		return maximum, nil
	case "p95", "p99":
		numerator := int64(95)
		if calculation == "p99" {
			numerator = 99
		}
		// ceil(N*p/100), with integer arithmetic rather than float64 ranks.
		rank := new(big.Int).Mul(new(big.Int).SetUint64(bucketCount), big.NewInt(numerator))
		rank.Add(rank, big.NewInt(99))
		rank.Quo(rank, big.NewInt(100))
		zeroCount := bucketCount - uint64(len(samples))
		zero := new(big.Int).SetUint64(zeroCount)
		if rank.Cmp(zero) <= 0 {
			return new(big.Rat), nil
		}
		rank.Sub(rank, zero)
		sort.Slice(samples, func(i, j int) bool { return samples[i].value.Cmp(samples[j].value) < 0 })
		if !rank.IsUint64() || rank.Uint64() < 1 || rank.Uint64() > uint64(len(samples)) {
			return nil, errors.New("invalid flow percentile rank")
		}
		return new(big.Rat).Set(samples[rank.Uint64()-1].value), nil
	default:
		return nil, errors.New("unsupported flow metric calculation")
	}
}
