// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func capacityCounterPair(tenant string) (capacityCounterPoint, capacityCounterPoint) {
	before := capacityCounterPoint{tenant: tenant, context: "owned-context", router: "owned-router", iface: "owned-interface", source: "authenticated-snmp-source", incarnation: "current-source-epoch", continuity: "independently-verified-device-continuity", at: time.Unix(1700000000, 123456789), exact: true, width: 64, octets: 1<<53 + 1, maxBitsPerSecond: 1_000_000_000}
	after := before
	after.at, after.octets = before.at.Add(1500*time.Millisecond), before.octets+1234
	return before, after
}

func TestCapacityCounterRatesKeepExactWideValuesBothWrapWidthsAndObservedZero(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		before, after := capacityCounterPair(tenant)
		original := after
		got, err := capacityCounterInterval(ctx, before, after, 1<<20, 1<<20)
		if err != nil || !got.observed || got.wrapped || got.bytes != "1234" || got.numerator != "19744" || got.denominator != "3" || after != original || !got.from.Equal(before.at) || !got.to.Equal(after.at) {
			t.Fatal("capacity counter rate rounded original uint64 values or elapsed duration", got, err)
		}
		for _, width := range []uint8{32, 64} {
			before, after = capacityCounterPair(tenant)
			before.width, after.width = width, width
			before.octets, after.octets = ^uint64(0)-9, 10
			if width == 32 {
				before.octets = 1<<32 - 10
			}
			after.at = before.at.Add(time.Second)
			got, err = capacityCounterInterval(ctx, before, after, 1<<20, 1<<20)
			if err != nil || !got.observed || !got.wrapped || got.bytes != "20" || got.numerator != "160" || got.denominator != "1" {
				t.Fatal("capacity counter lost a uniquely proven 32/64-bit wrap", width, got, err)
			}
		}
		before, after = capacityCounterPair(tenant)
		after.octets = before.octets
		got, err = capacityCounterInterval(ctx, before, after, 1<<20, 1<<20)
		if err != nil || !got.observed || got.wrapped || got.bytes != "0" || got.numerator != "0" || got.denominator != "1" || got.reason != "" {
			t.Fatal("observed zero counter delta became missing evidence", got, err)
		}
	}
}

func TestCapacityCounterRatesRefuseResetAmbiguousAndUnprovenInputsWithoutInventedZeros(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	for _, scenario := range []string{"legacy-rounded", "missing-continuity", "source-replaced", "reset", "width-changed", "capacity-missing", "capacity-changed", "over-capacity", "rising-hidden-wrap", "falling-multiple-wraps", "wide-capacity-overflow"} {
		t.Run(scenario, func(t *testing.T) {
			before, after := capacityCounterPair("red")
			want := ""
			switch scenario {
			case "legacy-rounded":
				after.exact, want = false, "exact_counter_unavailable"
			case "missing-continuity":
				after.continuity, want = "", "continuity_unavailable"
			case "source-replaced":
				after.incarnation, want = "another-source-epoch", "source_or_counter_continuity_changed"
			case "reset":
				after.continuity, want = "new-device-boot", "source_or_counter_continuity_changed"
			case "width-changed":
				after.width, want = 32, "counter_width_changed"
			case "capacity-missing":
				after.maxBitsPerSecond, want = 0, "physical_capacity_unavailable"
			case "capacity-changed":
				after.maxBitsPerSecond, want = 100_000_000, "physical_capacity_changed"
			case "over-capacity":
				before.maxBitsPerSecond, after.maxBitsPerSecond = 8, 8
				want = "counter_exceeds_physical_capacity"
			case "rising-hidden-wrap", "falling-multiple-wraps":
				before.width, after.width = 32, 32
				before.octets, after.octets = 100, 200
				if scenario == "falling-multiple-wraps" {
					before.octets, after.octets = 1<<32-10, 10
				}
				before.maxBitsPerSecond, after.maxBitsPerSecond = 100_000_000_000, 100_000_000_000
				after.at = before.at.Add(5 * time.Minute)
				want = "ambiguous_counter_wraps"
			case "wide-capacity-overflow":
				before.maxBitsPerSecond, after.maxBitsPerSecond = ^uint64(0), ^uint64(0)
				after.at = before.at.Add(10 * time.Second)
				want = "ambiguous_counter_wraps"
			}
			got, err := capacityCounterInterval(ctx, before, after, 1<<20, 1<<20)
			if err != nil || got.observed || got.wrapped || got.reason != want || got.bytes != "" || got.numerator != "" || got.denominator != "" {
				t.Fatal("unknown capacity interval invented traffic or guessed one wrap", scenario, got, err)
			}
		})
	}
}

func TestCapacityCounterRatesKeepTenantScopeCancellationAndWholeAdmission(t *testing.T) {
	before, after := capacityCounterPair("red")
	if got, err := capacityCounterInterval(t.Context(), before, after, 1<<20, 1<<20); !errors.Is(err, tenancy.ErrNoTenant) || !reflect.DeepEqual(got, capacityCounterRate{}) {
		t.Fatal("capacity counter arithmetic preceded its outer tenant boundary", got, err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	foreignBefore := before
	foreignBefore.tenant = "blue"
	if got, err := capacityCounterInterval(ctx, foreignBefore, after, 1<<20, 1<<20); err == nil || !reflect.DeepEqual(got, capacityCounterRate{}) {
		t.Fatal("capacity counter reused another tenant's original observation", got, err)
	}
	for _, change := range []func(*capacityCounterPoint){
		func(p *capacityCounterPoint) { p.tenant = "blue" },
		func(p *capacityCounterPoint) { p.context = "another-context" },
		func(p *capacityCounterPoint) { p.router = "another-router" },
		func(p *capacityCounterPoint) { p.iface = "another-interface" },
		func(p *capacityCounterPoint) { p.source = "another-source" },
		func(p *capacityCounterPoint) { p.width = 16 },
		func(p *capacityCounterPoint) { p.at = before.at },
	} {
		bad := after
		change(&bad)
		got, err := capacityCounterInterval(ctx, before, bad, 1<<20, 1<<20)
		// A changed width is an explicit unknown; an unsupported stable width
		// below is malformed. Scope/time changes never expose partial results.
		if bad.width != before.width {
			if err != nil || got.observed || got.reason != "counter_width_changed" {
				t.Fatal("capacity counter lost explicit width-change uncertainty", got, err)
			}
		} else if err == nil || !reflect.DeepEqual(got, capacityCounterRate{}) {
			t.Fatal("capacity counter crossed scope or exposed a partial malformed interval", got, err)
		}
	}
	for _, budget := range [][2]int64{{1, 1 << 20}, {1 << 20, 1}} {
		if got, err := capacityCounterInterval(ctx, before, after, budget[0], budget[1]); err == nil || !reflect.DeepEqual(got, capacityCounterRate{}) {
			t.Fatal("unadmitted capacity counter arithmetic exposed a partial interval", got, err)
		}
	}
	before.width, after.width = 16, 16
	if _, err := capacityCounterInterval(ctx, before, after, 1<<20, 1<<20); err == nil {
		t.Fatal("unsupported counter wire width was silently narrowed")
	}
	before, after = capacityCounterPair("red")
	for _, values := range [][2]uint64{{1 << 32, 0}, {0, 1 << 32}} {
		before.width, after.width = 32, 32
		before.octets, after.octets = values[0], values[1]
		if got, err := capacityCounterInterval(ctx, before, after, 1<<20, 1<<20); err == nil || !reflect.DeepEqual(got, capacityCounterRate{}) {
			t.Fatal("out-of-width capacity counter was truncated into its wire domain", got, err)
		}
	}
	before, after = capacityCounterPair("red")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := capacityCounterInterval(canceled, before, after, 1<<20, 1<<20); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, capacityCounterRate{}) {
		t.Fatal("canceled capacity counter arithmetic retained work or output", got, err)
	}
}
