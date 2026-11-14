// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPathHealthErrorBaselineKeepsWrappedOriginalRatesAndTenantIdentity(t *testing.T) {
	for _, tenant := range []string{"a", "b"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		base := pathHealthProjectionRows()[0]
		var rows []flowstore.CounterRow
		for i, value := range []uint64{4294967288, 4294967289, 4294967290, 4294967291, 15} {
			point := base
			point.TenantID, point.Name, point.Value, point.Width = tenant, "probectl.device.if.in.fcs.errors", value, 32
			point.PollStartedAt = base.PollStartedAt.Add(time.Duration(i) * time.Second)
			point.PollCompletedAt = point.PollStartedAt.Add(time.Millisecond)
			point.UptimeTicks += uint32(i) * 100
			point.CaptureKey[0], point.RawDigest[0] = byte(i+1), byte(i+10)
			rows = append(rows, point)
		}
		end := rows[len(rows)-1].PollCompletedAt
		trends, err := projectPathHealthErrorTrends(ctx, rows, end, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		rising := 0
		for _, trend := range trends {
			if trend.State != "rising_minimum_rate" {
				continue
			}
			rising++
			if trend.Metric != "probectl.device.if.in.fcs.errors" || trend.Model != "local-zscore-v1" || trend.BaselineSamples != 3 || trend.BaselineMean == nil || *trend.BaselineMean != 1 || len(trend.Observations) != 4 || trend.Observations[3].MinimumDelta != "20" || trend.Observations[3].PreviousValue != "4294967291" || trend.Observations[3].Value != "15" || trend.RateKind != "minimum_under_counter_continuity" {
				t.Fatalf("baseline lost original wrapped rates or qualified provenance: %+v", trend)
			}
		}
		if rising != 1 {
			t.Fatal("one planted rise did not produce one assessment", rising)
		}
		rows[len(rows)-1].TenantID = "foreign"
		if _, err := projectPathHealthErrorTrends(ctx, rows, end, time.Minute); !errors.Is(err, flowstore.ErrCounterHistoryInput) {
			t.Fatal("baseline learned from another tenant", err)
		}
		rows[len(rows)-1].TenantID = tenant
		rows[len(rows)-1].DiscontinuityTicks++
		trends, err = projectPathHealthErrorTrends(ctx, rows, end, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		for _, trend := range trends {
			if trend.Metric == rows[0].Name && (trend.State != "rate_unavailable" || len(trend.Observations) != 0) {
				t.Fatal("counter reset trained a rising-rate baseline", trend)
			}
		}
	}
}
