// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPeeringEstimateCombinesIntervalsBeforeExactPercentile(t *testing.T) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	window := peeringEstimateWindow{from: from, to: from.Add(100 * time.Minute), interval: 5 * time.Minute, memoryBytes: 16 << 20, workUnits: 16 << 20}
	var facts []peeringIntervalFact
	for i := range 20 {
		at := from.Add(time.Duration(i) * window.interval)
		window.complete = append(window.complete, at)
		for link := range 2 {
			// Each link: nineteen 1-Gbps intervals, one 100-Gbps interval.
			// Peaks differ: combined series has eighteen 2s and two 101s.
			// Its nearest-rank p95 is 101, while sum(link p95) is only 2.
			gbps := int64(1)
			if i == link {
				gbps = 100
			}
			facts = append(facts, peeringIntervalFact{tenantID: "red", start: at, bytes: big.NewInt(gbps * 37_500_000_000)})
		}
	}
	ctx := tenancy.WithTenant(t.Context(), "red")
	got, err := peeringTrafficPercentile(ctx, window, facts)
	if err != nil || got.rank != 19 || got.intervals != 20 || got.nonzero != 20 || got.bitsPerSecond.Cmp(big.NewRat(101_000_000_000, 1)) != 0 {
		t.Fatal("combined-interval hand p95 differs from eighteen 2s and two 101s", got, err)
	}
	if facts[0].bytes.Cmp(big.NewInt(3_750_000_000_000)) != 0 {
		t.Fatal("peering arithmetic mutated an input counter")
	}
	// Zero-filled, completely observed intervals stay in the percentile.
	zero, err := peeringTrafficPercentile(ctx, window, nil)
	if err != nil || zero.bitsPerSecond.Sign() != 0 || zero.nonzero != 0 {
		t.Fatal("observed zero traffic was confused with missing coverage", err)
	}
	wide := new(big.Int).Lsh(big.NewInt(1), 128)
	wideFacts := make([]peeringIntervalFact, 0, 40)
	for _, at := range window.complete {
		wideFacts = append(wideFacts, peeringIntervalFact{"red", at, wide}, peeringIntervalFact{"red", at, wide})
	}
	large, err := peeringTrafficPercentile(ctx, window, wideFacts)
	if err != nil || large.bytes.Cmp(new(big.Int).Lsh(big.NewInt(1), 129)) != 0 || wide.BitLen() != 129 {
		t.Fatal("peering aggregate narrowed complete traffic values", err)
	}
}

func TestPeeringEstimateRefusesForeignMissingPartialAndUnadmittedInputs(t *testing.T) {
	from := time.Now().UTC().Truncate(time.Second)
	base := peeringEstimateWindow{from: from, to: from.Add(time.Second), interval: time.Second, complete: []time.Time{from}, memoryBytes: 1 << 20, workUnits: 1 << 20}
	for _, fact := range []peeringIntervalFact{{"blue", from, big.NewInt(1)}, {"red", from, nil}, {"red", from, big.NewInt(-1)}, {"red", from.Add(time.Nanosecond), big.NewInt(1)}, {"red", from.Add(time.Second), big.NewInt(1)}} {
		if got, err := peeringTrafficPercentile(tenancy.WithTenant(t.Context(), "red"), base, []peeringIntervalFact{fact}); err == nil || got.bytes != nil {
			t.Fatal("peering estimate exposed partial or foreign traffic")
		}
	}
	for _, change := range []func(*peeringEstimateWindow){func(w *peeringEstimateWindow) { w.complete = nil }, func(w *peeringEstimateWindow) { w.memoryBytes = 1 }, func(w *peeringEstimateWindow) { w.workUnits = 1 }, func(w *peeringEstimateWindow) { w.to = w.to.Add(time.Nanosecond) }} {
		window := base
		change(&window)
		if got, err := peeringTrafficPercentile(tenancy.WithTenant(t.Context(), "red"), window, nil); err == nil || got.bytes != nil {
			t.Fatal("peering estimate manufactured complete coverage or admission")
		}
	}
	if got, err := peeringTrafficPercentile(t.Context(), base, nil); err == nil || got.bytes != nil {
		t.Fatal("peering estimate accepted missing tenant")
	}
	ctx, cancel := context.WithCancel(tenancy.WithTenant(t.Context(), "red"))
	cancel()
	if got, err := peeringTrafficPercentile(ctx, base, nil); err == nil || got.bytes != nil {
		t.Fatal("canceled peering estimate returned traffic")
	}
}
