// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"math/bits"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// EstimatePeeringTrafficRatesP95 preserves arbitrary window bounds. A final
// partial interval is ranked by its exact duration-normalized rate, not its
// byte count or an invented full-width denominator. Complete still describes
// observed inputs only; it must not be supplied by public request JSON.
func EstimatePeeringTrafficRatesP95(ctx context.Context, window PeeringTrafficWindow, facts []PeeringTrafficFact) (PeeringTrafficPercentile, error) {
	none := PeeringTrafficPercentile{}
	tenant, present := tenancy.FromContext(ctx)
	if !present {
		return none, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	span := window.To.Sub(window.From)
	if window.Interval <= 0 || span <= 0 || !window.From.Add(span).Equal(window.To) || window.MemoryBytes <= 0 || window.WorkUnits <= 0 {
		return none, errPeeringEstimateInput
	}
	if span%window.Interval == 0 {
		return EstimatePeeringTrafficP95(ctx, window, facts)
	}
	count := int64((span-1)/window.Interval) + 1
	if count != int64(len(window.Complete)) || count > window.MemoryBytes/1024 || count > window.WorkUnits/1024 || int64(len(facts)) > window.MemoryBytes/256 {
		return none, errPeeringEstimateInput
	}
	memory, work := window.MemoryBytes-count*1024, window.WorkUnits-count*1024
	maxBits := int64(1)
	for _, fact := range facts {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if fact.TenantID != tenant.String() || fact.Bytes == nil || fact.Bytes.Sign() < 0 || fact.Start.Before(window.From) || !fact.Start.Before(window.To) || fact.Start.Sub(window.From)%window.Interval != 0 {
			return none, errPeeringEstimateInput
		}
		width := int64(fact.Bytes.BitLen()) + int64(len(fact.TenantID)) + 256
		if width > memory/8 || width > work/8 {
			return none, errPeeringEstimateInput
		}
		memory, work = memory-width*8, work-width*8
		maxBits = max(maxBits, int64(fact.Bytes.BitLen()))
	}
	// Include complete sums, exact rational comparisons and decimal output.
	compareWidth := maxBits + int64(bits.Len(uint(len(facts)))) + 64
	comparisons := int64(bits.Len64(uint64(count))) * count
	if compareWidth > work/max(1, comparisons) || compareWidth > memory/max(1, count) {
		return none, errPeeringEstimateInput
	}
	type interval struct {
		start time.Time
		bytes *big.Int
		rate  *big.Rat
	}
	values := make([]interval, int(count))
	for i, at := range window.Complete {
		if !at.Equal(window.From.Add(time.Duration(i) * window.Interval)) {
			return none, errPeeringEstimateInput
		}
		values[i] = interval{start: at, bytes: new(big.Int)}
	}
	for _, fact := range facts {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		index := int(fact.Start.Sub(window.From) / window.Interval)
		values[index].bytes.Add(values[index].bytes, fact.Bytes)
	}
	nonzero := 0
	for i := range values {
		if values[i].bytes.Sign() != 0 {
			nonzero++
		}
		duration := min(window.Interval, window.To.Sub(values[i].start))
		numerator := new(big.Int).Mul(values[i].bytes, big.NewInt(8_000_000_000))
		values[i].rate = new(big.Rat).SetFrac(numerator, big.NewInt(int64(duration)))
	}
	slices.SortFunc(values, func(a, b interval) int {
		if order := a.rate.Cmp(b.rate); order != 0 {
			return order
		}
		return a.start.Compare(b.start)
	})
	if err := ctx.Err(); err != nil {
		return none, err
	}
	rank := int(count - count/20)
	selected := values[rank-1]
	return PeeringTrafficPercentile{Bytes: selected.bytes.String(), BitsPerSecondNumerator: selected.rate.Num().String(), BitsPerSecondDenominator: selected.rate.Denom().String(), Intervals: int(count), Rank: rank, Nonzero: nonzero}, nil
}
