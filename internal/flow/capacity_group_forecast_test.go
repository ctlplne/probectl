// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRegionalCapacityGroupShowsFirstCompleteForecastWithoutInventingAggregate(t *testing.T) {
	for index, tenant := range []string{"red", "blue"} {
		t.Run(tenant, func(t *testing.T) {
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			base := int64(100 + index*500)
			growing := capacityForecastFixture(tenant, 2, base, true, false)
			baseline := capacityForecastFixture(tenant, 2, base, false, false)
			window := CapacityMeasurementWindow{From: growing.from, To: growing.to, MemoryBytes: 512 << 20, WorkUnits: 16 << 30}
			uplink := CapacityCounterSource{TenantID: tenant, ContextID: "same-pop", DeviceID: "same-edge", InterfaceID: "uplink",
				AgentID: "same-lab-agent", SourceRef: "same-counter", SourceAssignedAt: growing.from.Add(-time.Hour), AgentAssignedAt: growing.from.Add(-time.Hour)}
			access := uplink
			access.InterfaceID = "access"
			members := []CapacityMeasuredMember{
				{source: uplink, in: growing.samples, out: baseline.samples},
				{source: access, in: slices.Clone(baseline.samples), out: baseline.samples},
			}
			last := &members[1].in[len(baseline.samples)-1]
			original := *last
			*last = capacityCounterRate{from: last.from, to: last.to, reason: "counter_poll_gap"}
			selected := CapacityForecastGroupInput{Kind: []string{"pop", "tower"}[index],
				Thresholds: []CapacityGroupThreshold{
					{ContextID: "same-pop", InterfaceID: "uplink", CapacityBPS: fmt.Sprint(base + 578)},
					{ContextID: "same-pop", InterfaceID: "access", CapacityBPS: fmt.Sprint(base + 10000)},
				},
			}
			got, err := ForecastGroupMembers(ctx, window, selected, "in", growing.until, members)
			if err != nil || got.Kind != selected.Kind || len(got.Members) != 2 || got.MembersWithoutCompleteForecast != 1 {
				t.Fatal("the group did not retain its complete authorized member set", got, err)
			}
			front := got.FirstConstraint
			expectedStart := growing.to.Add(70 * time.Minute)
			if front == nil || front.InterfaceID != "uplink" || front.Direction != "in" || front.Window.From == nil || !front.Window.From.Equal(expectedStart) {
				t.Fatal("first observed link forecast missed the known curve", front, expectedStart)
			}
			if fit := got.Members[1].Forecasts[0]; fit.Trained || fit.Reason != "training_coverage_incomplete" || fit.LastSample != nil {
				t.Fatal("an incomplete link was promoted to a measured rate or forecast", fit)
			}
			groupRates, err := ForecastCapacityMeasured(ctx, window, "same-pop", "in", fmt.Sprint(base+18000), growing.until, members)
			if err != nil || len(groupRates) != 1 || groupRates[0].LastSampleKnown || groupRates[0].LastSample != nil {
				t.Fatal("aggregate utilization was fabricated across the missing last interval", groupRates, err)
			}
			*last = original
			groupRates, err = ForecastCapacityMeasured(ctx, window, "same-pop", "in", fmt.Sprint(base+18000), growing.until, members)
			wantRate := big.NewRat(7*(2*base+240)+4031, 7)
			wantUtilization := new(big.Rat).Quo(wantRate, big.NewRat(base+18000, 1))
			if err != nil || len(groupRates) != 1 || !groupRates[0].CoverageComplete || groupRates[0].LastSample == nil ||
				groupRates[0].LastSample.BPS != wantRate.RatString() || groupRates[0].LastSample.Utilization != wantUtilization.RatString() {
				t.Fatal("aggregate did not preserve the exact aligned link observations", groupRates, err)
			}
			foreign := tenancy.WithTenant(t.Context(), tenancy.ID("unrelated"))
			if denied, err := ForecastGroupMembers(foreign, window, selected, "in", growing.until, members); err == nil || denied != nil {
				t.Fatal("a foreign caller received the original group", denied)
			}
		})
	}
}
