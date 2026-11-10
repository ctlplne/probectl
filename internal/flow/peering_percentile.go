// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// PeeringTrafficWindow is a storage-verified complete observation grid. It
// describes observed query inputs, never proof of lossless network telemetry.
// The service establishes coverage and current source authority separately;
// clients cannot supply this structure as a completeness or access grant.
type PeeringTrafficWindow struct {
	From, To               time.Time
	Interval               time.Duration
	Complete               []time.Time
	MemoryBytes, WorkUnits int64
}

type PeeringTrafficFact struct {
	TenantID string
	Start    time.Time
	Bytes    *big.Int
}

// PeeringTrafficPercentile preserves exact counters and rational rates. Human
// display may round these values, but acceptance/export arithmetic must not.
type PeeringTrafficPercentile struct {
	Bytes, BitsPerSecondNumerator, BitsPerSecondDenominator string
	Intervals, Rank, Nonzero                                int
}

// EstimatePeeringTrafficP95 combines eligible traffic per interval before
// ranking. It consumes private, already-authorized source observations; it
// neither chooses eligible peers nor infers an unobserved bucket was zero.
func EstimatePeeringTrafficP95(ctx context.Context, window PeeringTrafficWindow, observations []PeeringTrafficFact) (PeeringTrafficPercentile, error) {
	none := PeeringTrafficPercentile{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return none, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	count := int64(len(observations))
	if window.MemoryBytes <= 0 || window.WorkUnits <= 0 || count > window.MemoryBytes/128 || count > window.WorkUnits/128 {
		return none, errPeeringEstimateInput
	}
	for _, fact := range observations {
		if fact.TenantID != tenant.String() {
			return none, errPeeringEstimateInput
		}
	}
	facts := make([]peeringIntervalFact, len(observations))
	for i, fact := range observations {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		facts[i] = peeringIntervalFact{tenantID: fact.TenantID, start: fact.Start, bytes: fact.Bytes}
	}
	result, err := peeringTrafficPercentile(ctx, peeringEstimateWindow{from: window.From, to: window.To, interval: window.Interval, complete: window.Complete, memoryBytes: window.MemoryBytes - count*128, workUnits: window.WorkUnits - count*128}, facts)
	if err != nil {
		return none, err
	}
	// Decimal conversion is part of complete output admission. An exact wide
	// counter is retained or refused whole, never narrowed to a machine word.
	width := int64(result.bytes.BitLen()) + int64(result.bitsPerSecond.Num().BitLen()) + int64(result.bitsPerSecond.Denom().BitLen()) + 256
	if width > window.MemoryBytes/8 || width > window.WorkUnits/8 {
		return none, errPeeringEstimateInput
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return PeeringTrafficPercentile{Bytes: result.bytes.String(), BitsPerSecondNumerator: result.bitsPerSecond.Num().String(), BitsPerSecondDenominator: result.bitsPerSecond.Denom().String(), Intervals: result.intervals, Rank: result.rank, Nonzero: result.nonzero}, nil
}
