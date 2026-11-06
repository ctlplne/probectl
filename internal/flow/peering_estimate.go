// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"math/big"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var errPeeringEstimateInput = errors.New("complete owned peering intervals are required")

// These are private, already-authorized query facts, never a public request or
// source of routing/IX membership authority. A complete grid is independent of
// nonzero traffic: a missing bucket is not an observed zero. The eventual store
// adapter must establish tenant scope and current route/role/IX eligibility.
type peeringIntervalFact struct {
	tenantID string
	start    time.Time
	bytes    *big.Int
}

type peeringEstimateWindow struct {
	from, to               time.Time
	interval               time.Duration
	complete               []time.Time
	memoryBytes, workUnits int64
}

type peeringPercentile struct {
	bytes                    *big.Int
	bitsPerSecond            *big.Rat
	intervals, rank, nonzero int
}

// peeringTrafficPercentile combines all eligible traffic in each interval BEFORE
// selecting p95. Adding per-link percentiles loses coincident/different peaks.
// All arithmetic is exact; traffic values and input facts are never truncated,
// rounded through floats, mutated, or limited to machine-width aggregate sums.
func peeringTrafficPercentile(ctx context.Context, window peeringEstimateWindow, facts []peeringIntervalFact) (peeringPercentile, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return peeringPercentile{}, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return peeringPercentile{}, err
	}
	count, err := admitPeeringWindow(window, facts)
	if err != nil {
		return peeringPercentile{}, err
	}
	values := make([]*big.Int, count)
	for i, at := range window.complete {
		if !at.Equal(window.from.Add(time.Duration(i) * window.interval)) {
			return peeringPercentile{}, errPeeringEstimateInput
		}
		values[i] = new(big.Int)
	}
	for _, fact := range facts {
		if err := ctx.Err(); err != nil {
			return peeringPercentile{}, err
		}
		if fact.tenantID != tenant.String() || fact.bytes == nil || fact.bytes.Sign() < 0 || fact.start.Before(window.from) || !fact.start.Before(window.to) {
			return peeringPercentile{}, errPeeringEstimateInput
		}
		delta := fact.start.Sub(window.from)
		if delta%window.interval != 0 {
			return peeringPercentile{}, errPeeringEstimateInput
		}
		i := int(delta / window.interval)
		values[i].Add(values[i], fact.bytes)
	}
	nonzero := 0
	for _, value := range values {
		if value.Sign() != 0 {
			nonzero++
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Cmp(values[j]) < 0 })
	if err := ctx.Err(); err != nil {
		return peeringPercentile{}, err
	}
	// ceil(.95*n) = n-floor(n/20), without n*95 overflow or float rounding.
	rank := count - count/20
	bytes := new(big.Int).Set(values[rank-1])
	bits := new(big.Int).Mul(bytes, big.NewInt(8_000_000_000))
	rate := new(big.Rat).SetFrac(bits, big.NewInt(int64(window.interval)))
	return peeringPercentile{bytes: bytes, bitsPerSecond: rate, intervals: count, rank: rank, nonzero: nonzero}, nil
}

func admitPeeringWindow(window peeringEstimateWindow, facts []peeringIntervalFact) (int, error) {
	if window.interval <= 0 || !window.to.After(window.from) || window.memoryBytes <= 0 || window.workUnits <= 0 {
		return 0, errPeeringEstimateInput
	}
	span := window.to.Sub(window.from)
	if span == time.Duration(1<<63-1) || !window.from.Add(span).Equal(window.to) || span%window.interval != 0 {
		return 0, errPeeringEstimateInput
	}
	count := int64(span / window.interval)
	// Complete grid, sums, sorting and output are admitted together. No count
	// cap or fixed historical duration replaces actual resource admission.
	if count <= 0 || count != int64(len(window.complete)) || count > window.memoryBytes/512 || count > window.workUnits/512 {
		return 0, errPeeringEstimateInput
	}
	memory, work := window.memoryBytes-count*512, window.workUnits-count*512
	for _, fact := range facts {
		if fact.bytes == nil {
			return 0, errPeeringEstimateInput
		}
		charge := int64(fact.bytes.BitLen()/8) + int64(len(fact.tenantID)) + 256
		if charge > memory/4 || charge > work/4 {
			return 0, errPeeringEstimateInput
		}
		memory, work = memory-charge*4, work-charge*4
	}
	return int(count), nil
}
