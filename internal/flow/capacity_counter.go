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
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var errCapacityCounterInput = errors.New("complete scoped exact capacity counters are required")

// This private calculation input is not a read grant or public request. The
// eventual source reader must independently authorize the original context,
// interface and source, and prove continuity from exact poll/uptime/reset
// evidence. A caller-provided continuity string cannot confer that proof.
type capacityCounterPoint struct {
	tenant, context, router, iface  string
	source, incarnation, continuity string
	at                              time.Time
	exact                           bool
	width                           uint8
	octets, maxBitsPerSecond        uint64
	intervalReason                  string // Derived from original poll clocks, never supplied by a public query.
}

type capacityCounterRate struct {
	from, to                      time.Time
	bytes, numerator, denominator string
	bytesDenominator              string // Empty means whole observed octets; gridding may produce an exact fraction.
	reason                        string
	observed, wrapped             bool
}

// capacityCounterInterval performs only exact arithmetic over already scoped
// observations. Even a rising counter may hide whole wraps: the physical upper
// bound must leave exactly one possible modular delta. Missing/ambiguous/reset
// inputs remain unknown, never an invented zero or a guessed single wrap.
func capacityCounterInterval(ctx context.Context, before, after capacityCounterPoint, memoryBytes, workUnits int64) (capacityCounterRate, error) {
	none := capacityCounterRate{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return none, tenancy.ErrNoTenant
	}
	if before.tenant != tenant.String() || after.tenant != tenant.String() {
		return none, errCapacityCounterInput
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if memoryBytes < 4096 || workUnits < 4096 {
		return none, errCapacityCounterInput
	}
	memoryBytes, workUnits = memoryBytes-4096, workUnits-4096
	for _, point := range []capacityCounterPoint{before, after} {
		for _, value := range []string{point.tenant, point.context, point.router, point.iface, point.source, point.incarnation, point.continuity, point.intervalReason} {
			if err := ctx.Err(); err != nil {
				return none, err
			}
			size := int64(len(value))
			if size > memoryBytes/16 || size > workUnits/16 || strings.TrimSpace(value) != value {
				return none, errCapacityCounterInput
			}
			memoryBytes, workUnits = memoryBytes-size*16, workUnits-size*16
		}
	}
	if before.context == "" || before.router == "" || before.iface == "" || before.source == "" || before.context != after.context || before.router != after.router || before.iface != after.iface || before.source != after.source {
		return none, errCapacityCounterInput
	}
	elapsed := after.at.Sub(before.at)
	if before.at.IsZero() || after.at.IsZero() || elapsed <= 0 || !before.at.Add(elapsed).Equal(after.at) {
		return none, errCapacityCounterInput
	}
	out := capacityCounterRate{from: before.at, to: after.at}
	unknown := func(reason string) (capacityCounterRate, error) {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		out.reason = reason
		return out, nil
	}
	if after.intervalReason != "" {
		return unknown(after.intervalReason)
	}
	if !before.exact || !after.exact {
		return unknown("exact_counter_unavailable")
	}
	if before.incarnation == "" || before.continuity == "" || after.incarnation == "" || after.continuity == "" {
		return unknown("continuity_unavailable")
	}
	if before.incarnation != after.incarnation || before.continuity != after.continuity {
		return unknown("source_or_counter_continuity_changed")
	}
	if before.width != after.width {
		return unknown("counter_width_changed")
	}
	if before.width != 32 && before.width != 64 {
		return none, errCapacityCounterInput
	}
	if before.width == 32 && (before.octets > 1<<32-1 || after.octets > 1<<32-1) {
		return none, errCapacityCounterInput
	}
	if before.maxBitsPerSecond == 0 || after.maxBitsPerSecond == 0 {
		return unknown("physical_capacity_unavailable")
	}
	if before.maxBitsPerSecond != after.maxBitsPerSecond {
		return unknown("physical_capacity_changed")
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(before.width))
	delta := new(big.Int).Sub(new(big.Int).SetUint64(after.octets), new(big.Int).SetUint64(before.octets))
	wrapped := delta.Sign() < 0
	if wrapped {
		delta.Add(delta, modulus)
	}
	maximum := new(big.Int).Mul(new(big.Int).SetUint64(before.maxBitsPerSecond), big.NewInt(int64(elapsed)))
	maximum.Quo(maximum, big.NewInt(8_000_000_000))
	if delta.Cmp(maximum) > 0 {
		return unknown("counter_exceeds_physical_capacity")
	}
	if new(big.Int).Add(new(big.Int).Set(delta), modulus).Cmp(maximum) <= 0 {
		return unknown("ambiguous_counter_wraps")
	}
	rate := new(big.Rat).SetFrac(new(big.Int).Mul(new(big.Int).Set(delta), big.NewInt(8_000_000_000)), big.NewInt(int64(elapsed)))
	if err := ctx.Err(); err != nil {
		return none, err
	}
	out.bytes, out.numerator, out.denominator = delta.String(), rate.Num().String(), rate.Denom().String()
	out.observed, out.wrapped = true, wrapped
	return out, nil
}
