// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// RoutingTransferHandoff separates the circuit's complete billing population
// from the one physical egress on which the moved traffic is observed.
// The caller supplies already-authorized source and agreement facts.
type RoutingTransferHandoff struct {
	Agreement      CapacityAgreement
	Members        []CapacityMeasuredMember
	EgressID       string
	EgressSpeedBPS uint64
}

// RoutingTransferInterval carries the sampled prefix's offered traffic over
// one agreed billing interval. Nil means missing coverage, including an absent
// original egress attribution. An observed zero is a non-nil zero rate.
type RoutingTransferInterval struct {
	From, To time.Time
	MovedBPS *big.Rat
}

type routingTransferMemberKey struct{ context, id string }

type RoutingTransferBill struct {
	AgreementID string                   `json:"agreement_id"`
	Version     string                   `json:"agreement_version"`
	BeforeP95   CapacityPercentileResult `json:"before_p95"`
	AfterP95    CapacityPercentileResult `json:"after_p95"`
	Before      CapacityBillResult       `json:"before"`
	After       CapacityBillResult       `json:"after"`
}

type RoutingTransferEstimate struct {
	From                    time.Time            `json:"from"`
	To                      time.Time            `json:"to"`
	Status                  string               `json:"status"`
	Reason                  string               `json:"reason,omitempty"`
	MovedPeakBPS            string               `json:"moved_peak_bps,omitempty"`
	CandidatePeakBPS        string               `json:"candidate_peak_bps,omitempty"`
	CandidateEgressSpeedBPS string               `json:"candidate_egress_speed_bps,omitempty"`
	CandidateEgressLimitBPS string               `json:"candidate_egress_limit_bps,omitempty"`
	Source                  *RoutingTransferBill `json:"source,omitempty"`
	Candidate               *RoutingTransferBill `json:"candidate,omitempty"`
	Currency                string               `json:"currency,omitempty"`
	NetChargeChange         string               `json:"net_charge_change,omitempty"`
}

// EstimateRoutingEgressTransfer shifts exact interval rates before re-ranking
// either circuit. It does not grant current route, pricing or actor authority.
func EstimateRoutingEgressTransfer(ctx context.Context, window CapacityMeasurementWindow, routingContext string,
	source, candidate RoutingTransferHandoff, intervals []RoutingTransferInterval) (RoutingTransferEstimate, error) {
	none := RoutingTransferEstimate{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return none, tenancy.ErrNoTenant
	}
	span := window.To.Sub(window.From)
	if !capacityAgreementUUID(routingContext) || window.From.IsZero() || span <= 0 || !window.From.Add(span).Equal(window.To) ||
		int64(len(intervals)) != int64(1+(span-1)/(5*time.Minute)) || source.Agreement.ID == candidate.Agreement.ID {
		return none, ErrCapacityAgreementInvalid
	}
	part := window
	part.MemoryBytes, part.WorkUnits = window.MemoryBytes/5, window.WorkUnits/8
	remaining := capacityGridAdmission{memory: part.MemoryBytes, work: window.WorkUnits / 2}
	if !remaining.debit(int64(len(intervals)), 4096, 4096) {
		return none, ErrCapacityAgreementBudget
	}
	seen := map[routingTransferMemberKey]bool{}
	findEgress := func(handoff RoutingTransferHandoff) (CapacityMeasuredMember, error) {
		return routingTransferEgress(ctx, tenant.String(), routingContext, handoff, seen, &remaining)
	}
	fromPort, err := findEgress(source)
	if err != nil {
		return none, err
	}
	toPort, err := findEgress(candidate)
	if err != nil {
		return none, err
	}
	result := RoutingTransferEstimate{From: window.From.UTC(), To: window.To.UTC(), Status: "unavailable"}
	limit := min(candidate.EgressSpeedBPS, toPort.source.PhysicalMaxBPS)
	if limit == 0 {
		result.Reason = "candidate_capacity_unknown"
		return result, nil
	}
	result.CandidateEgressSpeedBPS = strconv.FormatUint(candidate.EgressSpeedBPS, 10)
	result.CandidateEgressLimitBPS = strconv.FormatUint(limit, 10)
	projectedSource, projectedCandidate, err := shiftRoutingTransferGrid(ctx, window, fromPort, toPort, intervals, limit, &remaining, &result)
	if err != nil || result.Reason != "" {
		return result, err
	}
	result.Source, err = priceRoutingTransfer(ctx, part, source, projectedSource)
	if err != nil {
		return none, err
	}
	result.Candidate, err = priceRoutingTransfer(ctx, part, candidate, projectedCandidate)
	if err != nil {
		return none, err
	}
	if !result.Source.After.Complete || !result.Candidate.After.Complete || !result.Source.Before.Complete || !result.Candidate.Before.Complete {
		result.Reason = "billing_coverage_incomplete"
		return result, nil
	}
	result.Status = "estimated"
	if result.Source.After.Currency == result.Candidate.After.Currency {
		result.Currency = result.Source.After.Currency
		total, err := routingTransferChargeChange(&remaining, result.Source, result.Candidate)
		if err != nil {
			return none, err
		}
		result.NetChargeChange = total.RatString()
	} else {
		result.Reason = "agreement_currencies_differ"
	}
	return result, ctx.Err()
}

func routingTransferEgress(ctx context.Context, tenant, routingContext string, handoff RoutingTransferHandoff,
	seen map[routingTransferMemberKey]bool, budget *capacityGridAdmission) (CapacityMeasuredMember, error) {
	var selected CapacityMeasuredMember
	a := handoff.Agreement
	if a.TenantID != tenant {
		return selected, tenancy.ErrNoTenant
	}
	if !capacityAgreementUUID(a.ID) || a.Version == "" || a.Version != a.CurrentVersion || !a.TargetPresent ||
		!capacityAgreementUUID(handoff.EgressID) || len(handoff.Members) == 0 {
		return selected, ErrCapacityAgreementInvalid
	}
	if !budget.debit(int64(len(handoff.Members)), 4096, 4096) {
		return selected, ErrCapacityAgreementBudget
	}
	for _, member := range handoff.Members {
		if err := ctx.Err(); err != nil {
			return selected, err
		}
		s := member.source
		if s.TenantID != tenant {
			return selected, tenancy.ErrNoTenant
		}
		key := routingTransferMemberKey{s.ContextID, s.InterfaceID}
		if !capacityAgreementUUID(s.ContextID) || !capacityAgreementUUID(s.InterfaceID) || seen[key] {
			return selected, ErrCapacityAgreementInvalid
		}
		seen[key] = true
		if s.InterfaceID == handoff.EgressID && s.ContextID == routingContext {
			selected = member
		}
	}
	if selected.source.InterfaceID == "" {
		return selected, ErrCapacityAgreementInvalid
	}
	return selected, nil
}

func shiftRoutingTransferGrid(ctx context.Context, window CapacityMeasurementWindow, fromPort, toPort CapacityMeasuredMember,
	intervals []RoutingTransferInterval, limit uint64, budget *capacityGridAdmission, result *RoutingTransferEstimate) (CapacityMeasuredMember, CapacityMeasuredMember, error) {
	if len(fromPort.out) != len(intervals) || len(toPort.out) != len(intervals) {
		return fromPort, toPort, ErrCapacityAgreementInvalid
	}
	fromPort.out, toPort.out = slices.Clone(fromPort.out), slices.Clone(toPort.out)
	capacity := new(big.Rat).SetUint64(limit)
	movedPeak, candidatePeak := new(big.Rat), new(big.Rat)
	for i, item := range intervals {
		if err := ctx.Err(); err != nil {
			return fromPort, toPort, err
		}
		start := window.From.Add(time.Duration(i) * 5 * time.Minute)
		end := start.Add(min(5*time.Minute, window.To.Sub(start)))
		if !item.From.Equal(start) || !item.To.Equal(end) {
			return fromPort, toPort, ErrCapacityAgreementInvalid
		}
		from, fromKnown, err := capacityBillingBytes(ctx, fromPort.out[i], start, end)
		if err != nil {
			return fromPort, toPort, err
		}
		to, toKnown, err := capacityBillingBytes(ctx, toPort.out[i], start, end)
		if err != nil {
			return fromPort, toPort, err
		}
		if item.MovedBPS == nil || !fromKnown || !toKnown {
			result.Reason = "transfer_interval_incomplete"
			return fromPort, toPort, nil
		}
		if item.MovedBPS.Sign() < 0 {
			return fromPort, toPort, ErrCapacityAgreementInvalid
		}
		if !budget.arithmetic(item.MovedBPS, from, to, capacity) {
			return fromPort, toPort, ErrCapacityAgreementBudget
		}
		octetsPerBPS := big.NewRat(int64(end.Sub(start)), 8_000_000_000)
		moved := new(big.Rat).Mul(item.MovedBPS, octetsPerBPS)
		if moved.Cmp(from) > 0 {
			result.Reason = "prefix_volume_exceeds_source_egress"
			return fromPort, toPort, nil
		}
		from.Sub(from, moved)
		to.Add(to, moved)
		var offered big.Rat
		offered.Quo(to, octetsPerBPS)
		if item.MovedBPS.Cmp(movedPeak) > 0 {
			movedPeak.Set(item.MovedBPS)
		}
		if offered.Cmp(candidatePeak) > 0 {
			candidatePeak.Set(&offered)
		}
		fromPort.out[i] = routingTransferRate(start, end, from, octetsPerBPS)
		toPort.out[i] = routingTransferRate(start, end, to, octetsPerBPS)
	}
	if movedPeak.Sign() == 0 {
		result.Reason = "no_observed_traffic_to_move"
		return fromPort, toPort, nil
	}
	result.MovedPeakBPS, result.CandidatePeakBPS = movedPeak.RatString(), candidatePeak.RatString()
	if candidatePeak.Cmp(capacity) > 0 {
		result.Reason = "projected_egress_exceeds_capacity"
	}
	return fromPort, toPort, nil
}

func routingTransferRate(from, to time.Time, octets, octetsPerBPS *big.Rat) capacityCounterRate {
	bps := new(big.Rat).Quo(octets, octetsPerBPS)
	return capacityCounterRate{from: from, to: to, observed: true, bytes: octets.Num().String(), bytesDenominator: octets.Denom().String(),
		numerator: bps.Num().String(), denominator: bps.Denom().String()}
}

func priceRoutingTransfer(ctx context.Context, window CapacityMeasurementWindow, handoff RoutingTransferHandoff, projected CapacityMeasuredMember) (*RoutingTransferBill, error) {
	definition := handoff.Agreement.Definition
	actual, err := CalculateCapacityMeasuredP95(ctx, window, definition.Direction, handoff.Members)
	if err != nil {
		return nil, err
	}
	members := slices.Clone(handoff.Members)
	for i, member := range members {
		if member.source.InterfaceID == handoff.EgressID && member.source.ContextID == projected.source.ContextID {
			members[i] = projected
			break
		}
	}
	after, err := CalculateCapacityMeasuredP95(ctx, window, definition.Direction, members)
	if err != nil {
		return nil, err
	}
	beforeBill, err := CheckCapacityMeasuredBill(ctx, definition, actual, "", window.MemoryBytes/4, window.WorkUnits/4)
	if err != nil {
		return nil, err
	}
	afterBill, err := CheckCapacityMeasuredBill(ctx, definition, after, "", window.MemoryBytes/4, window.WorkUnits/4)
	if err != nil {
		return nil, err
	}
	return &RoutingTransferBill{AgreementID: handoff.Agreement.ID, Version: handoff.Agreement.Version,
		BeforeP95: actual.Result(), AfterP95: after.Result(), Before: beforeBill, After: afterBill}, nil
}

func routingTransferChargeChange(budget *capacityGridAdmission, source, candidate *RoutingTransferBill) (*big.Rat, error) {
	net := new(big.Rat)
	for i, bill := range []CapacityBillResult{source.After, candidate.After, source.Before, candidate.Before} {
		text := bill.ChargeNumerator + "/" + bill.ChargeDenominator
		if !budget.debit(int64(len(text)), 64, 64) {
			return nil, ErrCapacityAgreementBudget
		}
		charge, ok := new(big.Rat).SetString(text)
		if !ok || !budget.arithmetic(charge, net) {
			return nil, ErrCapacityAgreementBudget
		}
		if i < 2 {
			net.Add(net, charge)
		} else {
			net.Sub(net, charge)
		}
	}
	return net, nil
}
