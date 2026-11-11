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

func TestPeeringPartialIntervalRanksExactCombinedRatesWithoutTruncatingWindow(t *testing.T) {
	from := time.Unix(1700000000, 123456789).UTC()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	window := PeeringTrafficWindow{From: from, To: from.Add(5 * time.Second), Interval: 2 * time.Second, Complete: []time.Time{from, from.Add(2 * time.Second), from.Add(4 * time.Second)}, MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	facts := []PeeringTrafficFact{{"red", from, big.NewInt(60)}, {"red", from, big.NewInt(40)}, {"red", from.Add(2 * time.Second), big.NewInt(125)}, {"red", from.Add(4 * time.Second), big.NewInt(75)}}
	got, err := EstimatePeeringTrafficRatesP95(ctx, window, facts)
	if err != nil || got.Bytes != "75" || got.BitsPerSecondNumerator != "600" || got.BitsPerSecondDenominator != "1" || got.Intervals != 3 || got.Rank != 3 || got.Nonzero != 3 {
		t.Fatal("partial interval lost exact full-window combined rate", got, err)
	}
	window.To = from.Add(4*time.Second + time.Nanosecond)
	facts[3].Bytes = big.NewInt(1)
	got, err = EstimatePeeringTrafficRatesP95(ctx, window, facts)
	if err != nil || got.BitsPerSecondNumerator != "8000000000" || got.BitsPerSecondDenominator != "1" {
		t.Fatal("one-nanosecond observed tail was rounded or dropped", got, err)
	}
	facts[3].Bytes = new(big.Int).Lsh(big.NewInt(1), 256)
	got, err = EstimatePeeringTrafficRatesP95(ctx, window, facts)
	want := new(big.Int).Mul(facts[3].Bytes, big.NewInt(8_000_000_000)).String()
	if err != nil || got.BitsPerSecondNumerator != want || facts[0].Bytes.String() != "60" || facts[3].Bytes.BitLen() != 257 {
		t.Fatal("partial interval narrowed or mutated exact counters", got, err)
	}
}

func TestPeeringPartialIntervalRefusesMissingForeignCanceledAndUnadmittedInputs(t *testing.T) {
	from := time.Unix(1700000000, 0).UTC()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	window := PeeringTrafficWindow{From: from, To: from.Add(3 * time.Second), Interval: 2 * time.Second, Complete: []time.Time{from, from.Add(2 * time.Second)}, MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	facts := []PeeringTrafficFact{{"red", from, big.NewInt(0)}}
	for _, change := range []func(*PeeringTrafficWindow, []PeeringTrafficFact){
		func(w *PeeringTrafficWindow, _ []PeeringTrafficFact) { w.Complete = nil },
		func(w *PeeringTrafficWindow, _ []PeeringTrafficFact) { w.MemoryBytes = 1 },
		func(w *PeeringTrafficWindow, _ []PeeringTrafficFact) { w.WorkUnits = 1 },
		func(w *PeeringTrafficWindow, _ []PeeringTrafficFact) {
			w.Complete = []time.Time{from, from.Add(time.Second)}
		},
		func(_ *PeeringTrafficWindow, f []PeeringTrafficFact) { f[0].TenantID = "blue" },
		func(_ *PeeringTrafficWindow, f []PeeringTrafficFact) { f[0].Start = from.Add(time.Second) },
	} {
		bad, copyFacts := window, append([]PeeringTrafficFact{}, facts...)
		change(&bad, copyFacts)
		if got, err := EstimatePeeringTrafficRatesP95(ctx, bad, copyFacts); err == nil || !reflect.DeepEqual(got, PeeringTrafficPercentile{}) {
			t.Fatal("partial interval accepted missing, foreign or unadmitted evidence", got, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := EstimatePeeringTrafficRatesP95(canceled, window, facts); err == nil || got.Bytes != "" {
		t.Fatal("canceled partial estimate exposed output", got, err)
	}
	got, err := EstimatePeeringTrafficRatesP95(ctx, window, facts)
	if err != nil || got.Bytes != "0" || got.Nonzero != 0 {
		t.Fatal("observed zero became missing evidence", got, err)
	}
}
