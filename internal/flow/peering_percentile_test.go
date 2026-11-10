// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPeeringPercentileServiceSeamKeepsExactCombinedRateAndObservedZeros(t *testing.T) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	window := PeeringTrafficWindow{From: from, To: from.Add(100 * time.Minute), Interval: 5 * time.Minute, MemoryBytes: 16 << 20, WorkUnits: 16 << 20}
	var facts []PeeringTrafficFact
	for i := range 20 {
		at := from.Add(time.Duration(i) * window.Interval)
		window.Complete = append(window.Complete, at)
		for link := range 2 {
			gbps := int64(1)
			if i == link {
				gbps = 100
			}
			facts = append(facts, PeeringTrafficFact{TenantID: "red", Start: at, Bytes: big.NewInt(gbps * 37_500_000_000)})
		}
	}
	ctx := tenancy.WithTenant(t.Context(), "red")
	got, err := EstimatePeeringTrafficP95(ctx, window, facts)
	if err != nil || got.Intervals != 20 || got.Rank != 19 || got.Nonzero != 20 || got.Bytes != "3787500000000" || got.BitsPerSecondNumerator != "101000000000" || got.BitsPerSecondDenominator != "1" {
		t.Fatal("peering service changed combined-interval hand p95 or exact rate", got, err)
	}
	zero, err := EstimatePeeringTrafficP95(ctx, window, nil)
	if err != nil || zero.Bytes != "0" || zero.BitsPerSecondNumerator != "0" || zero.BitsPerSecondDenominator != "1" || zero.Nonzero != 0 {
		t.Fatal("peering service confused a complete observed zero grid with missing data", zero, err)
	}
	wide := new(big.Int).Lsh(big.NewInt(1), 256)
	for i := range facts {
		facts[i].Bytes = wide
	}
	large, err := EstimatePeeringTrafficP95(ctx, window, facts)
	if err != nil || large.Bytes != new(big.Int).Lsh(big.NewInt(1), 257).String() || wide.BitLen() != 257 {
		t.Fatal("peering service clipped a wide counter or mutated its input", large, err)
	}
}

func TestPeeringPercentileServiceSeamRefusesForeignMissingAndPartialInputs(t *testing.T) {
	from := time.Now().UTC().Truncate(time.Second)
	window := PeeringTrafficWindow{From: from, To: from.Add(time.Second), Interval: time.Second, Complete: []time.Time{from}, MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	facts := []PeeringTrafficFact{{TenantID: "red", Start: from, Bytes: big.NewInt(1)}}
	for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), "blue")} {
		if got, err := EstimatePeeringTrafficP95(ctx, window, facts); err == nil || !reflect.DeepEqual(got, PeeringTrafficPercentile{}) {
			t.Fatal("peering service accepted missing or foreign source scope", got, err)
		}
	}
	ctx := tenancy.WithTenant(t.Context(), "red")
	for _, change := range []func(*PeeringTrafficWindow){func(w *PeeringTrafficWindow) { w.Complete = nil }, func(w *PeeringTrafficWindow) { w.To = w.To.Add(time.Nanosecond) }, func(w *PeeringTrafficWindow) { w.MemoryBytes = 1 }, func(w *PeeringTrafficWindow) { w.WorkUnits = 1 }} {
		bad := window
		change(&bad)
		if got, err := EstimatePeeringTrafficP95(ctx, bad, facts); err == nil || got.Bytes != "" {
			t.Fatal("peering service published unadmitted or incomplete source observations", got, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := EstimatePeeringTrafficP95(canceled, window, facts); err == nil || got.Bytes != "" {
		t.Fatal("canceled peering service returned a result", got, err)
	}
}
