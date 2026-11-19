// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDDoSEpisodeRequiresAdjacentQualifyingTenantWindows(t *testing.T) {
	const tenant = "25ebf92b-c387-451d-9e67-0b323c402a58"
	view := "548baa36-4c4a-47a1-b7d8-7c7f48d36716"
	input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.0/24", Direction: "ingress", PeriodSeconds: 60,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
		MinObservedRecords: 50, MinObservedAddresses: 8}
	binding := QueryGroupBinding{TenantID: tenant, RuleID: "18df565b-2523-443a-b139-eab57d6c0f79", ViewID: view, ViewVersion: input.Version,
		Condition: QueryCondition{Mode: DDoSCondition, DDoS: &input}}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	budget := QueryGroupBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	at := time.Date(2026, 1, 12, 12, 0, 0, 0, time.UTC)
	atMinute := func(minute int, class anomaly.DDoSClass) flow.DDoSAssessment {
		end := at.Add(time.Duration(minute) * time.Minute)
		reference := flow.DDoSWindowEvidence{From: end.AddDate(0, 0, -7).Add(-time.Minute), To: end.AddDate(0, 0, -7),
			Source: "raw", Bytes: "100000", Packets: "1000", Citation: "original reference"}
		current := flow.DDoSWindowEvidence{From: end.Add(-time.Minute), To: end, Source: "raw", Bytes: "400000", Packets: "4000", Citation: "original current"}
		result := flow.DDoSAssessment{ViewID: view, Version: input.Version, Prefix: input.Prefix, Direction: input.Direction,
			Before: reference, After: current}
		if class != "" {
			result.Detection = &anomaly.DDoSDetection{Class: class, CurrentBytes: current.Bytes, CurrentPackets: current.Packets,
				ReferenceBytes: reference.Bytes, ReferencePackets: reference.Packets, CurrentCitation: current.Citation, ReferenceCitation: reference.Citation}
		}
		return result
	}
	isolated, warmed, err := EvaluateDDoSEpisode(ctx, binding, QueryGroupState{}, atMinute(1, ""), atMinute(2, anomaly.DDoSVolumetric), budget)
	if err != nil || isolated != nil || len(warmed.Keys) != 0 {
		t.Fatal("a benign isolated window opened an episode", err)
	}
	event, active, err := EvaluateDDoSEpisode(ctx, binding, warmed, atMinute(2, anomaly.DDoSVolumetric), atMinute(3, anomaly.DDoSVolumetric), budget)
	if err != nil || event == nil || !ValidFieldDigest(event.SignalID) || len(active.Keys) != 1 {
		t.Fatal("adjacent qualifying observations did not open one episode", err)
	}
	duplicate, lasting, err := EvaluateDDoSEpisode(ctx, binding, active, atMinute(3, anomaly.DDoSVolumetric), atMinute(4, anomaly.DDoSVolumetric), budget)
	if err != nil || duplicate != nil || len(lasting.Keys) != 1 {
		t.Fatal("one sustained observation opened multiple episodes", err)
	}
	if got, _, err := EvaluateDDoSEpisode(ctx, binding, lasting, atMinute(3, anomaly.DDoSVolumetric), atMinute(5, anomaly.DDoSVolumetric), budget); got != nil || !errors.Is(err, ErrQueryGroups) {
		t.Fatal("an incomplete clock sequence authorized a new episode", err)
	}
	other := tenancy.WithTenant(t.Context(), tenancy.ID("aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"))
	if got, _, err := EvaluateDDoSEpisode(other, binding, warmed, atMinute(2, anomaly.DDoSVolumetric), atMinute(3, anomaly.DDoSVolumetric), budget); got != nil || !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("a sibling context evaluated the owned traffic grouping", err)
	}
}
