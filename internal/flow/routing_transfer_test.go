// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingEgressTransferRepricesTheWholeGridAndChecksPeakCapacity(t *testing.T) {
	const (
		tenant             = "10000000-0000-4000-8000-000000000001"
		otherTenant        = "10000000-0000-4000-8000-000000000002"
		contextID          = "10000000-0000-4000-8000-000000000003"
		sourceID           = "10000000-0000-4000-8000-000000000004"
		candidateID        = "10000000-0000-4000-8000-000000000005"
		sourceAgreement    = "10000000-0000-4000-8000-000000000006"
		candidateAgreement = "10000000-0000-4000-8000-000000000007"
	)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const duration = 5 * time.Minute
	const samples = 20
	window := CapacityMeasurementWindow{From: start, To: start.Add(samples * duration), MemoryBytes: 128 << 20, WorkUnits: 128 << 20}
	handoff := func(iface, agreement, commit, price string) RoutingTransferHandoff {
		return RoutingTransferHandoff{EgressID: iface, Agreement: CapacityAgreement{ID: agreement, TenantID: tenant,
			Version: "1", CurrentVersion: "1", TargetPresent: true, Definition: CapacityAgreementDefinition{
				Direction: "out", CommitBPS: commit, UnitBPS: "1", UnitPrice: price, Currency: "USD",
			}}, Members: []CapacityMeasuredMember{{source: CapacityCounterSource{TenantID: tenant, ContextID: contextID,
			InterfaceID: iface, DeviceID: contextID, AgentID: "issued-snmp", SourceRef: "owned-handoff", PhysicalMaxBPS: 1000}}}}
	}
	source := handoff(sourceID, sourceAgreement, "100", "4")
	candidate := handoff(candidateID, candidateAgreement, "50", "1")
	candidate.EgressSpeedBPS = 1000
	intervals := make([]RoutingTransferInterval, samples)
	octetsPerBPS := big.NewRat(int64(duration), 8_000_000_000)
	rate := func(from, to time.Time, bps int64) capacityCounterRate {
		return routingTransferRate(from, to, new(big.Rat).Mul(big.NewRat(bps, 1), octetsPerBPS), octetsPerBPS)
	}
	for i := range intervals {
		from := start.Add(time.Duration(i) * duration)
		to := from.Add(duration)
		oldSource, oldCandidate, moved := int64(80), int64(70), int64(0)
		switch i {
		case 0:
			oldSource, oldCandidate, moved = 400, 30, 360
		case 1:
			oldSource, oldCandidate, moved = 200, 300, 20
		}
		intervals[i] = RoutingTransferInterval{From: from, To: to, MovedBPS: big.NewRat(moved, 1)}
		for _, item := range []struct {
			member *CapacityMeasuredMember
			out    int64
		}{{&source.Members[0], oldSource}, {&candidate.Members[0], oldCandidate}} {
			item.member.in = append(item.member.in, rate(from, to, 0))
			item.member.out = append(item.member.out, rate(from, to, item.out))
		}
	}
	got, err := EstimateRoutingEgressTransfer(ctx, window, contextID, source, candidate, intervals)
	if err != nil || got.Status != "estimated" || got.Reason != "" || got.Currency != "USD" || got.NetChargeChange != "-150" ||
		got.CandidatePeakBPS != "390" || got.MovedPeakBPS != "360" || got.Source.BeforeP95.BPSNumerator != "200" ||
		got.Source.AfterP95.BPSNumerator != "80" || got.Candidate.BeforeP95.BPSNumerator != "70" || got.Candidate.AfterP95.BPSNumerator != "320" ||
		got.Source.After.ChargeNumerator != "400" || source.Members[0].out[0].numerator != "400" {
		t.Fatalf("did not move the traffic before reranking both complete bills or changed original evidence: %+v %v", got, err)
	}
	candidate.Members[0].source.PhysicalMaxBPS = 380
	if got, err := EstimateRoutingEgressTransfer(ctx, window, contextID, source, candidate, intervals); err != nil ||
		got.Reason != "projected_egress_exceeds_capacity" || got.CandidatePeakBPS != "390" || got.Candidate != nil ||
		got.CandidateEgressSpeedBPS != "1000" || got.CandidateEgressLimitBPS != "380" {
		t.Fatalf("intermittent physical overload was priced as feasible: %+v %v", got, err)
	}
	candidate.Members[0].source.PhysicalMaxBPS = 1000
	intervals[samples-1].MovedBPS = nil
	if got, err := EstimateRoutingEgressTransfer(ctx, window, contextID, source, candidate, intervals); err != nil ||
		got.Reason != "transfer_interval_incomplete" || got.NetChargeChange != "" {
		t.Fatalf("missing prefix interval was silently treated as zero: %+v %v", got, err)
	}
	candidate.Members[0].source.TenantID = otherTenant
	if got, err := EstimateRoutingEgressTransfer(ctx, window, contextID, source, candidate, intervals); !errors.Is(err, tenancy.ErrNoTenant) || got.Candidate != nil {
		t.Fatalf("foreign circuit member was admitted to the requested tenant: %+v %v", got, err)
	}
}
