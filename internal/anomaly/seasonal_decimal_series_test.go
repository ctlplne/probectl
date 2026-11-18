// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"errors"
	"testing"
	"time"
)

func TestExactSeasonalFlowCompareKeepsSubFloatCounterChangeAndTenant(t *testing.T) {
	const tenant = "owned-series"
	const median = "1000000000000000000000000000000000000001"
	const upper = "1000000000000000000000000000000000000002"
	const change = "1000000000000000000000000000000000000003"
	model, err := NewWeeklySeasonalModel(WeeklySeasonalConfig{Timezone: "America/New_York", MinimumDays: 3, MinimumDeviation: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 18, 0, 0, 0, time.UTC)
	at, _ := model.LatestCompletedSlot(now)
	feature := Feature{TenantID: tenant, Plane: "flow", Source: "saved-explorer", Subject: "exact-owned-group", Metric: "bytes:total"}
	var history []ExactSeasonalFeature
	for _, end := range model.ComparableCompleteEnds(at) {
		point := feature
		point.TS = end.Add(-time.Millisecond)
		point.Citation = "flow:" + point.TS.Format(time.RFC3339Nano)
		history = append(history, ExactSeasonalFeature{Feature: point, Decimal: median})
	}
	feature.TS, feature.Citation = at, "flow:current"
	current := ExactSeasonalFeature{Feature: feature, Decimal: change}
	out, err := model.CompareDecimalSeries(t.Context(), tenant, current, history, 3, 1<<20)
	if err != nil || out.State != SeasonalUp || out.Band == nil || out.Band.Current != change || out.Band.Median != median || out.Band.Upper != upper ||
		out.ComparableDays != 6 || len(out.Citations) != 3 {
		t.Fatalf("could not distinguish exact counters on the same scale: %+v (%v)", out, err)
	}
	history[0].TenantID = "sibling"
	if out, err := model.CompareDecimalSeries(t.Context(), tenant, current, history, 3, 1<<20); !errors.Is(err, ErrCrossTenantFeature) || out.Band != nil {
		t.Fatal("a foreign feature reached the exact training population", err)
	}
}
