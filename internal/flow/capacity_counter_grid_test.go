// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func capacityGridFixture(tenant string, width uint8) (capacityCounterGridWindow, []capacityCounterPoint) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 123456789, time.UTC)
	window := capacityCounterGridWindow{from: from, to: from.Add(10*time.Minute + time.Second), maximumPollGap: 7 * time.Second, memoryBytes: 64 << 20, workUnits: 64 << 20}
	base := uint64(1<<53 + 1)
	if width == 32 {
		base = 1<<32 - 20
	}
	var points []capacityCounterPoint
	for at := from.Add(-time.Second); !at.After(window.to.Add(7 * time.Second)); at = at.Add(7 * time.Second) {
		value := base + uint64(len(points))
		if width == 32 {
			value %= 1 << 32
		}
		points = append(points, capacityCounterPoint{tenant: tenant, context: "area", router: "router", iface: "port", source: "issued source", incarnation: "current binding", continuity: "verified boot/discontinuity", at: at, exact: true, width: width, octets: value, maxBitsPerSecond: 1_000_000_000})
	}
	return window, points
}

func TestCapacityCounterGridKeepsExactPollMeansWrapsPartialTailAndCircuitP95(t *testing.T) {
	if capacityCounterGridModel != "counter_poll_mean_overlap" {
		t.Fatal("resampling must state its within-poll mean-rate assumption")
	}
	for _, tenant := range []string{"red", "blue"} {
		for _, width := range []uint8{32, 64} {
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			window, points := capacityGridFixture(tenant, width)
			grid, err := capacityCounterGrid(ctx, window, points)
			if err != nil || len(grid) != 3 {
				t.Fatal("complete non-aligned counter polls did not produce a whole grid", err)
			}
			for i, sample := range grid {
				want := "300"
				if i == 2 {
					want = "1"
				}
				if !sample.observed || sample.bytes != want || sample.bytesDenominator != "7" || sample.numerator != "8" || sample.denominator != "7" || sample.reason != "" {
					t.Fatal("grid rounded fractional octets, widened the tail or lost a wrap", width, i, sample)
				}
			}
			if !grid[0].from.Equal(window.from) || !grid[2].to.Equal(window.to) || grid[0].wrapped != (width == 32) {
				t.Fatal("resampling replaced original clocks or discarded wrap provenance", grid)
			}
			member := capacityBillingMember{tenant: tenant, context: "area", router: "router", iface: "port", source: "issued source", incarnation: "current binding"}
			for _, sample := range grid {
				member.samples = append(member.samples, capacityBillingSample{in: sample, out: sample})
			}
			other := member
			other.iface = "second port"
			other.samples = append([]capacityBillingSample(nil), member.samples...)
			for i := range other.samples {
				for _, rate := range []*capacityCounterRate{&other.samples[i].in, &other.samples[i].out} {
					rate.bytesDenominator, rate.denominator = "11", "11"
				}
			}
			bill := capacityBillingWindow{from: window.from, to: window.to, mode: capacityBillingIn, memoryBytes: 64 << 20, workUnits: 64 << 20}
			p95, err := capacityBillingP95(ctx, bill, []capacityBillingMember{member, other})
			if err != nil || !p95.complete || p95.numerator != "144" || p95.denominator != "77" || p95.expected != 3 || p95.rank != 3 {
				t.Fatal("circuit p95 rounded gridded fractions or ranked members separately", p95, err)
			}
		}
	}
}

func TestCapacityCounterGridLeavesMissingPollsResetsAndUnbracketedEdgesUnknown(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	window, _ := capacityGridFixture("red", 64)
	missing, err := capacityCounterGrid(ctx, window, nil)
	if err != nil || len(missing) != 3 {
		t.Fatal("empty source history did not retain the entire requested period", err)
	}
	for _, sample := range missing {
		if sample.observed || sample.reason != "counter_coverage_incomplete" || sample.bytes != "" {
			t.Fatal("empty source history became observed zero", sample)
		}
	}
	for _, scenario := range []string{"missing poll", "reset", "missing first bracket", "exact counter unavailable"} {
		window, points := capacityGridFixture("red", 64)
		switch scenario {
		case "missing poll":
			points = append(points[:2], points[3:]...)
		case "reset":
			for i := 2; i < len(points); i++ {
				points[i].continuity = "new boot/discontinuity"
			}
		case "missing first bracket":
			points = points[1:]
		case "exact counter unavailable":
			points[2].exact = false
		}
		grid, err := capacityCounterGrid(ctx, window, points)
		if err != nil || len(grid) != 3 || grid[0].observed || grid[0].reason == "" || grid[0].bytes != "" || grid[0].bytesDenominator != "" || grid[0].numerator != "" || !grid[1].observed || !grid[2].observed {
			t.Fatal("missing/reset evidence became interpolated traffic or damaged independent intervals", scenario, grid, err)
		}
	}
}

func TestCapacityCounterGridRequiresOneTenantSourceAndWholeResourceAdmission(t *testing.T) {
	window, points := capacityGridFixture("red", 64)
	if grid, err := capacityCounterGrid(t.Context(), window, points); !errors.Is(err, tenancy.ErrNoTenant) || grid != nil {
		t.Fatal("counter gridding preceded the tenant boundary", err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	for _, scenario := range []string{"foreign tenant", "foreign interface", "foreign source", "duplicate clock", "memory", "work", "canceled"} {
		window, points := capacityGridFixture("red", 64)
		bound := ctx
		last := &points[len(points)-1]
		switch scenario {
		case "foreign tenant":
			last.tenant = "blue"
		case "foreign interface":
			last.iface = "another port"
		case "foreign source":
			last.source = "another source"
		case "duplicate clock":
			last.at = points[len(points)-2].at
		case "memory":
			window.memoryBytes = 1
		case "work":
			window.workUnits = 1
		case "canceled":
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			bound = canceled
		}
		if grid, err := capacityCounterGrid(bound, window, points); err == nil || grid != nil {
			t.Fatal("unscoped/unadmitted grid returned a successful prefix", scenario, err)
		}
	}
}
