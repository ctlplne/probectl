// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"math/big"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func peeringSummaryFixture(t *testing.T) (context.Context, peeringEstimateRequest, peeringTargetEligibility, flowstore.PeeringTrafficResult) {
	t.Helper()
	const tenant = "11111111-1111-4111-8111-111111111111"
	from := time.Unix(1700000000, 123456789).UTC()
	request := peeringEstimateRequest{Target: peeringTarget{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, InterfaceID: "33333333-3333-4333-8333-333333333333", PeerASN: ^uint32(0), IXID: 71, LANID: 11}, Direction: "inbound", From: from, To: from.Add(100 * time.Minute), BucketSeconds: 300}
	target := peeringTargetEligibility{Target: request.Target, Eligible: true}
	traffic := flowstore.PeeringTrafficResult{Source: "modeled-owned-traffic"}
	for i := 0; i < 20; i++ {
		for link := 0; link < 2; link++ {
			gbps := int64(1)
			if i == 18+link {
				gbps = 100
			}
			id := "44444444-4444-4444-8444-444444444444"
			if link == 1 {
				id = "55555555-5555-4555-8555-555555555555"
			}
			start := from.Add(time.Duration(i) * 5 * time.Minute)
			traffic.Buckets = append(traffic.Buckets, flowstore.PeeringTrafficBucket{Start: start, End: start.Add(5 * time.Minute), InterfaceID: id, Role: entity.InterfaceRoleTransit, State: "eligible", Bytes: new(big.Int).Mul(big.NewInt(gbps), big.NewInt(37_500_000_000)).String(), Flows: "1"})
		}
	}
	return tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), request, target, traffic
}

func TestPeeringSummaryCombinesTransitBeforeP95AndKeepsUnknownVolumes(t *testing.T) {
	ctx, request, target, traffic := peeringSummaryFixture(t)
	got, err := summarizePeeringTraffic(ctx, request, target, traffic, flowstore.DefaultExplorerBudget())
	if err != nil || !got.CompleteObservedInputs || !got.CompleteClassification || got.P95 == nil || got.P95.BitsPerSecondNumerator != "101000000000" || got.P95.BitsPerSecondDenominator != "1" || len(got.Transit) != 2 || got.ObservedIntervals != 20 {
		t.Fatal("peering service summed per-link percentiles or lost original hand calculation", got, err)
	}
	for _, link := range got.Transit {
		if link.P95.BitsPerSecondNumerator != "1000000000" {
			t.Fatal("per-transit hand calculation changed", link)
		}
	}
	for _, state := range []string{"ambiguous", "unavailable"} {
		bucket := traffic.Buckets[0]
		bucket.State, bucket.Bytes = state, "17000000000000000000"
		traffic.Buckets = append(traffic.Buckets, bucket)
	}
	unknown := traffic.Buckets[0]
	unknown.InterfaceID, unknown.Role, unknown.Bytes = "", entity.InterfaceRoleOther, "99"
	traffic.Buckets = append(traffic.Buckets, unknown)
	got, err = summarizePeeringTraffic(ctx, request, target, traffic, flowstore.DefaultExplorerBudget())
	if err != nil || !got.CompleteObservedInputs || got.CompleteClassification || got.Reason != "partial_routing_evidence" || got.Bytes["ambiguous_transit"] != "17000000000000000000" || got.Bytes["unavailable_transit"] != "17000000000000000000" || got.Bytes["unmapped_interface"] != "99" || got.P95 == nil || got.P95.BitsPerSecondNumerator != "101000000000" {
		t.Fatal("unknown evidence was hidden or promoted into eligible traffic", got, err)
	}
}

func TestPeeringSummaryKeepsMissingIntervalsUnprovenAndRefusesLateCorruption(t *testing.T) {
	ctx, request, target, traffic := peeringSummaryFixture(t)
	missing := traffic
	missing.Buckets = slices.Clone(traffic.Buckets[2:])
	got, err := summarizePeeringTraffic(ctx, request, target, missing, flowstore.DefaultExplorerBudget())
	if err != nil || got.CompleteObservedInputs || got.ObservedIntervals != 19 || got.ExpectedIntervals != 20 || got.P95 != nil || len(got.Transit) != 0 || got.Reason != "missing_observed_intervals" {
		t.Fatal("peering service manufactured observed zeros for a missing interval", got, err)
	}
	for _, change := range []func(*flowstore.PeeringTrafficBucket){
		func(b *flowstore.PeeringTrafficBucket) { b.Bytes = "-1" }, func(b *flowstore.PeeringTrafficBucket) { b.Flows = "0" },
		func(b *flowstore.PeeringTrafficBucket) { b.End = b.End.Add(time.Second) }, func(b *flowstore.PeeringTrafficBucket) { b.State = "guessed" },
	} {
		bad := traffic
		bad.Buckets = slices.Clone(traffic.Buckets)
		change(&bad.Buckets[len(bad.Buckets)-1])
		if got, err := summarizePeeringTraffic(ctx, request, target, bad, flowstore.DefaultExplorerBudget()); err == nil || !reflect.DeepEqual(got, peeringEstimateResult{}) {
			t.Fatal("late corrupt peering traffic exposed a partial estimate", got, err)
		}
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("66666666-6666-4666-8666-666666666666"))
	if got, err := summarizePeeringTraffic(foreign, request, target, traffic, flowstore.DefaultExplorerBudget()); err == nil || !reflect.DeepEqual(got, peeringEstimateResult{}) {
		t.Fatal("peering summary crossed its tenant boundary", err)
	}
}

func TestPeeringServiceRequiresCurrentTenantUserBeforeCaptureSelection(t *testing.T) {
	ctx, request, _, _ := peeringSummaryFixture(t)
	server := &Server{}
	reads := 0
	selector := func(context.Context) ([]flowstore.RoutingCaptureRead, error) { reads++; return nil, nil }
	selection := flowstore.PeeringQueryTarget{Scope: request.Target.Scope, RouterID: "44444444-4444-4444-8444-444444444444", PeerASN: request.Target.PeerASN, Direction: request.Direction}
	for _, actor := range []*auth.Principal{nil, {TenantID: request.Target.Scope.TenantID}, {TenantID: request.Target.Scope.TenantID, UserID: "owner"}} {
		if got, err := server.loadPeeringRoutingSnapshot(ctx, actor, selection, flowstore.DefaultExplorerBudget(), selector); err == nil || got.data != nil || reads != 0 {
			t.Fatal("peering capture selection preceded current user/source storage authority", err, reads)
		}
	}
	actor := &auth.Principal{TenantID: request.Target.Scope.TenantID, UserID: "owner"}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("66666666-6666-4666-8666-666666666666"))
	if got, err := server.estimatePeeringTraffic(foreign, actor, request); err == nil || !reflect.DeepEqual(got, peeringEstimateResult{}) {
		t.Fatal("peering service replaced a contradictory tenant credential", err)
	}
	request.Target.Scope.TenantID = "66666666-6666-4666-8666-666666666666"
	if got, err := server.estimatePeeringTraffic(ctx, actor, request); err == nil || !reflect.DeepEqual(got, peeringEstimateResult{}) {
		t.Fatal("peering service admitted a foreign target before tenant authorization", err)
	}
}
