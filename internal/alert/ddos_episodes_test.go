// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"errors"
	"strings"
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
		return ddosEpisodeFixtureWindow(binding, at.Add(time.Duration(minute)*time.Minute), class)
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

func TestFastDDoSEpisodeRemainsOpenAcrossQualifyingClassChanges(t *testing.T) {
	const owner = "25ebf92b-c387-451d-9e67-0b323c402a58"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	budget := QueryGroupBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: 5,
		BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
		VectorShareBasisPoints: 6000, MinObservedRecords: 50, MinObservedAddresses: 2,
		Application: &flow.DDoSApplicationBinding{Service: "sample-service", Port: 443}}
	binding := QueryGroupBinding{TenantID: owner, RuleID: "18df565b-2523-443a-b139-eab57d6c0f79",
		ViewID: "548baa36-4c4a-47a1-b7d8-7c7f48d36716", ViewVersion: input.Version,
		Condition: QueryCondition{Mode: DDoSCondition, DDoS: &input}}
	end := time.Date(2026, 1, 12, 12, 0, 0, 0, time.UTC)
	atWindow := func(offset int, class anomaly.DDoSClass) flow.DDoSAssessment {
		return ddosEpisodeFixtureWindow(binding, end.Add(time.Duration(offset)*5*time.Second), class)
	}
	volume := func(offset int) flow.DDoSAssessment {
		result := atWindow(offset, anomaly.DDoSVolumetric)
		result.Application = &anomaly.DDoSApplicationEvidence{
			Reference: anomaly.DDoSApplicationWindow{From: result.Before.From, To: result.Before.To, Digest: strings.Repeat("a", 64)},
			Current:   anomaly.DDoSApplicationWindow{From: result.After.From, To: result.After.To, Digest: strings.Repeat("b", 64)},
			State:     anomaly.DDoSApplicationDegraded,
		}
		return result
	}
	syn := func(offset int) flow.DDoSAssessment { return atWindow(offset, anomaly.DDoSSYN) }
	quiet := func(offset int) flow.DDoSAssessment { return atWindow(offset, "") }

	none, idle, err := EvaluateDDoSEpisode(ctx, binding, QueryGroupState{}, syn(0), volume(1), budget)
	if err != nil || none != nil || len(idle.Keys) != 0 {
		t.Fatal("mixed classifications cannot open a new episode", err)
	}
	first, active, err := EvaluateDDoSEpisode(ctx, binding, QueryGroupState{}, syn(2), syn(3), budget)
	if err != nil || first == nil || len(active.Keys) != 1 {
		t.Fatal("sustained pressure should open one original episode", err)
	}
	uncorroborated := atWindow(4, anomaly.DDoSVolumetric)
	if got, _, err := EvaluateDDoSEpisode(ctx, binding, active, syn(3), uncorroborated, budget); got != nil || !errors.Is(err, anomaly.ErrDDoSCoverage) {
		t.Fatal("the evaluation cannot advance when required application evidence is missing", err)
	}
	overload := volume(4)
	overload.Application.State = anomaly.DDoSApplicationOverload
	if got, _, err := EvaluateDDoSEpisode(ctx, binding, active, syn(3), overload, budget); got != nil || !errors.Is(err, anomaly.ErrDDoSCoverage) {
		t.Fatal("inconclusive overload cannot change the active episode", err)
	}
	for _, pair := range [][2]flow.DDoSAssessment{{syn(3), volume(4)}, {volume(4), syn(5)}, {syn(5), syn(6)}} {
		duplicate, next, err := EvaluateDDoSEpisode(ctx, binding, active, pair[0], pair[1], budget)
		if err != nil || duplicate != nil || len(next.Keys) != 1 || next.Keys[0] != first.GroupKey || !next.At.Equal(pair[1].After.To) {
			t.Fatal("qualifying adjacent observations should keep the same active episode", next, err)
		}
		active = next
	}
	sibling := tenancy.WithTenant(t.Context(), tenancy.ID("aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"))
	if got, _, err := EvaluateDDoSEpisode(sibling, binding, active, syn(6), volume(7), budget); got != nil || !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("the sibling cannot retain an owned active episode", err)
	}
	stopped, next, err := EvaluateDDoSEpisode(ctx, binding, active, syn(6), quiet(7), budget)
	if stopped != nil || err != nil || len(next.Keys) != 0 {
		t.Fatal("a complete quiet observation should clear the previous episode", err)
	}
	fresh, _, err := EvaluateDDoSEpisode(ctx, binding, next, syn(8), syn(9), budget)
	if err != nil || fresh == nil || fresh.GroupKey != first.GroupKey || fresh.SignalID == first.SignalID {
		t.Fatal("a later episode after complete quiet evidence should get its own receipt", err)
	}
}

func ddosEpisodeFixtureWindow(binding QueryGroupBinding, end time.Time, class anomaly.DDoSClass) flow.DDoSAssessment {
	input := binding.Condition.DDoS
	width := time.Duration(input.PeriodSeconds) * time.Second
	reference := flow.DDoSWindowEvidence{From: end.AddDate(0, 0, -7).Add(-width), To: end.AddDate(0, 0, -7),
		Source: "raw", Bytes: "100000", Packets: "1000", Citation: "original reference"}
	current := flow.DDoSWindowEvidence{From: end.Add(-width), To: end, Source: "raw", Bytes: "400000", Packets: "4000", Citation: "original current"}
	result := flow.DDoSAssessment{ViewID: binding.ViewID, Version: input.Version, Prefix: input.Prefix, Direction: input.Direction,
		Before: reference, After: current}
	if class != "" {
		result.Detection = &anomaly.DDoSDetection{Class: class, CurrentBytes: current.Bytes, CurrentPackets: current.Packets,
			ReferenceBytes: reference.Bytes, ReferencePackets: reference.Packets, CurrentCitation: current.Citation, ReferenceCitation: reference.Citation}
	}
	return result
}
