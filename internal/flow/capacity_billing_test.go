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
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func capacityBillingFixture(tenant string, count int) (capacityBillingWindow, capacityBillingMember) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	window := capacityBillingWindow{from: from, to: from.Add(time.Duration(count) * 5 * time.Minute), mode: capacityBillingIn, memoryBytes: 64 << 20, workUnits: 64 << 20}
	member := capacityBillingMember{tenant: tenant, context: "owned-context", router: "owned-router", iface: "owned-interface", source: "authenticated-snmp-source", incarnation: "current-incarnation", samples: make([]capacityBillingSample, count)}
	for i := range member.samples {
		start := from.Add(time.Duration(i) * 5 * time.Minute)
		member.samples[i] = capacityBillingSample{in: capacityBillingTestRate(start, start.Add(5*time.Minute), "0"), out: capacityBillingTestRate(start, start.Add(5*time.Minute), "0")}
	}
	return window, member
}

func capacityBillingTestRate(from, to time.Time, bytes string) capacityCounterRate {
	value, ok := new(big.Int).SetString(bytes, 10)
	if !ok {
		panic("malformed capacity test fixture")
	}
	rate := new(big.Rat).SetFrac(new(big.Int).Mul(value, big.NewInt(8_000_000_000)), big.NewInt(int64(to.Sub(from))))
	return capacityCounterRate{from: from, to: to, bytes: bytes, numerator: rate.Num().String(), denominator: rate.Denom().String(), observed: true}
}

func TestCapacityBillingP95KeepsDistinctDirectionalConventionsAndObservedZeros(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		window, member := capacityBillingFixture(tenant, 20)
		for i := range member.samples {
			inBytes, outBytes := "37500000000", "37500000000" // 1 Gbps.
			if i == 0 {
				inBytes = "3750000000000" // 100 Gbps, different directional peaks.
			}
			if i == 1 {
				outBytes = "3750000000000"
			}
			sample := &member.samples[i]
			sample.in = capacityBillingTestRate(sample.in.from, sample.in.to, inBytes)
			sample.out = capacityBillingTestRate(sample.out.from, sample.out.to, outBytes)
		}
		for _, scenario := range []struct {
			mode capacityBillingMode
			want string
		}{{capacityBillingIn, "1000000000"}, {capacityBillingOut, "1000000000"}, {capacityBillingMaxPercentiles, "1000000000"}, {capacityBillingIntervalMax, "100000000000"}, {capacityBillingIntervalSum, "101000000000"}} {
			window.mode = scenario.mode
			got, err := capacityBillingP95(ctx, window, []capacityBillingMember{member})
			if err != nil || !got.complete || got.expected != 20 || got.observed != 20 || got.missing != 0 || got.rank != 19 || got.numerator != scenario.want || got.denominator != "1" {
				t.Fatal("billing percentile conflated directional conventions or ranked rounded samples", scenario.mode, got, err)
			}
		}
		window, member = capacityBillingFixture(tenant, 120)
		got, err := capacityBillingP95(ctx, window, []capacityBillingMember{member})
		if err != nil || !got.complete || got.expected != 120 || got.rank != 114 || got.numerator != "0" || got.denominator != "1" {
			t.Fatal("complete observed zero billing grid became unknown or dropped the wrong five percent", got, err)
		}
	}
}

func TestCapacityBillingP95CombinesWholeCircuitGridBeforeRankingWithoutRounding(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		window, first := capacityBillingFixture(tenant, 20)
		_, second := capacityBillingFixture(tenant, 20)
		second.iface = "another-owned-interface"
		members := []capacityBillingMember{first, second}
		for link := range members {
			for i := range members[link].samples {
				bytes := "37500000000"
				if i == link {
					bytes = "3750000000000"
				}
				sample := &members[link].samples[i]
				sample.in = capacityBillingTestRate(sample.in.from, sample.in.to, bytes)
			}
		}
		got, err := capacityBillingP95(ctx, window, members)
		if err != nil || !got.complete || got.numerator != "101000000000" || got.denominator != "1" || got.rank != 19 {
			t.Fatal("circuit billing percentile lost the combined-grid hand calculation", got, err)
		}
		for _, member := range members {
			individual, err := capacityBillingP95(ctx, window, []capacityBillingMember{member})
			if err != nil || individual.numerator != "1000000000" {
				t.Fatal("circuit witness failed to distinguish summing member percentiles from the actual 101 Gbps", individual, err)
			}
		}
		window, first = capacityBillingFixture(tenant, 1)
		window.to = window.from.Add(1500 * time.Millisecond)
		wide := "18446744073709551617" // Greater than uint64, supplied by an already aggregated source.
		first.samples[0].in = capacityBillingTestRate(window.from, window.to, wide)
		first.samples[0].out = capacityBillingTestRate(window.from, window.to, "0")
		original := first.samples[0]
		got, err = capacityBillingP95(ctx, window, []capacityBillingMember{first})
		if err != nil || !got.complete || got.numerator != "295147905179352825872" || got.denominator != "3" || first.samples[0] != original {
			t.Fatal("billing percentile rounded wide counters, mutated facts or assumed a full-duration tail", got, err)
		}
	}
}

func TestCapacityBillingP95WithholdsIncompletePeriodsWithoutInventedZeroFill(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	window, member := capacityBillingFixture("red", 20)
	missing := member.samples[7].in
	missing.observed, missing.bytes, missing.numerator, missing.denominator, missing.reason = false, "", "", "", "ambiguous_counter_wraps"
	member.samples[7].in = missing
	for _, mode := range []capacityBillingMode{capacityBillingIn, capacityBillingMaxPercentiles, capacityBillingIntervalMax, capacityBillingIntervalSum} {
		window.mode = mode
		got, err := capacityBillingP95(ctx, window, []capacityBillingMember{member})
		if err != nil || got.complete || got.expected != 20 || got.observed != 19 || got.missing != 1 || got.rank != 0 || got.numerator != "" || got.denominator != "" {
			t.Fatal("incomplete billing period invented zero traffic or ranked only surviving samples", mode, got, err)
		}
	}
	window.mode = capacityBillingOut
	got, err := capacityBillingP95(ctx, window, []capacityBillingMember{member})
	if err != nil || !got.complete || got.numerator != "0" || got.observed != 20 {
		t.Fatal("unused directional uncertainty invalidated a complete observed output series", got, err)
	}
}

func TestCapacityBillingP95RefusesForeignDuplicateMalformedAndUnadmittedInputs(t *testing.T) {
	window, member := capacityBillingFixture("red", 20)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	if got, err := capacityBillingP95(t.Context(), window, []capacityBillingMember{member}); !errors.Is(err, tenancy.ErrNoTenant) || !reflect.DeepEqual(got, capacityBillingPercentile{}) {
		t.Fatal("billing calculation preceded its outer tenant boundary", got, err)
	}
	foreign := member
	foreign.tenant, foreign.iface = "blue", "foreign-interface"
	for _, members := range [][]capacityBillingMember{nil, {foreign}, {member, foreign}, {member, member}} {
		if got, err := capacityBillingP95(ctx, window, members); err == nil || !reflect.DeepEqual(got, capacityBillingPercentile{}) {
			t.Fatal("billing calculation admitted missing, duplicate or cross-tenant members", got, err)
		}
	}
	for _, change := range []func(*capacityBillingMember){
		func(m *capacityBillingMember) { m.source = "" },
		func(m *capacityBillingMember) { m.incarnation = "" },
		func(m *capacityBillingMember) { m.context = " padded " },
		func(m *capacityBillingMember) { m.samples = m.samples[:19] },
		func(m *capacityBillingMember) { m.samples[19].in.from = m.samples[18].in.from },
		func(m *capacityBillingMember) { m.samples[19].in.to = m.samples[19].in.to.Add(time.Nanosecond) },
		func(m *capacityBillingMember) { m.samples[19].in.denominator = "0" },
		func(m *capacityBillingMember) { m.samples[19].in.bytes = "01" },
		func(m *capacityBillingMember) { m.samples[19].in.bytes = "-1" },
		func(m *capacityBillingMember) { m.samples[19].in.numerator = "1e3" },
		func(m *capacityBillingMember) { m.samples[19].in.numerator = "1" },
		func(m *capacityBillingMember) { m.samples[19].in.observed = false },
	} {
		bad := member
		bad.samples = append([]capacityBillingSample(nil), member.samples...)
		change(&bad)
		if got, err := capacityBillingP95(ctx, window, []capacityBillingMember{bad}); err == nil || !reflect.DeepEqual(got, capacityBillingPercentile{}) {
			t.Fatal("malformed billing facts exposed a partial or falsely complete percentile", got, err)
		}
	}
	for _, change := range []func(*capacityBillingWindow){
		func(w *capacityBillingWindow) { w.mode = "guessed" },
		func(w *capacityBillingWindow) { w.to = w.from },
		func(w *capacityBillingWindow) { w.memoryBytes = 1 },
		func(w *capacityBillingWindow) { w.workUnits = 1 },
	} {
		bad := window
		change(&bad)
		if got, err := capacityBillingP95(ctx, bad, []capacityBillingMember{member}); err == nil || !reflect.DeepEqual(got, capacityBillingPercentile{}) {
			t.Fatal("unadmitted billing period exposed a partial percentile", got, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := capacityBillingP95(canceled, window, []capacityBillingMember{member}); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, capacityBillingPercentile{}) {
		t.Fatal("canceled billing calculation retained output", got, err)
	}
}
