// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"math/big"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type peeringTransitEstimate struct {
	InterfaceID string
	P95         flow.PeeringTrafficPercentile
}

// These are private service values. A served projection must keep coverage,
// unknown volumes and hypothetical-routing qualifications alongside numbers.
type peeringEstimateResult struct {
	Target                 peeringTargetEligibility
	Direction, Reason      string
	From, To               time.Time
	BucketSeconds          int
	ObservedIntervals      int
	ExpectedIntervals      int64
	CompleteObservedInputs bool
	CompleteClassification bool
	Source                 string
	Bytes                  map[string]string
	P95                    *flow.PeeringTrafficPercentile
	Transit                []peeringTransitEstimate
}

func summarizePeeringTraffic(ctx context.Context, request peeringEstimateRequest, target peeringTargetEligibility, traffic flowstore.PeeringTrafficResult, budget flowstore.ExplorerBudget) (peeringEstimateResult, error) {
	none := peeringEstimateResult{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant.String() != request.Target.Scope.TenantID || target.Target != request.Target || !target.Eligible {
		return none, entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	width, span := time.Duration(request.BucketSeconds)*time.Second, request.To.Sub(request.From)
	if budget.Validate() != nil || request.BucketSeconds <= 0 || request.BucketSeconds > flow.MaxPlanBucketSeconds || width <= 0 || span <= 0 || !request.From.Add(span).Equal(request.To) || int64(len(traffic.Buckets)) > budget.MemoryBytes/4096 {
		return none, flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	result := peeringEstimateResult{Target: target, Direction: request.Direction, From: request.From, To: request.To, BucketSeconds: request.BucketSeconds, Source: traffic.Source, ExpectedIntervals: int64((span-1)/width) + 1, CompleteClassification: true, Bytes: map[string]string{}}
	totals := map[string]*big.Int{}
	for _, name := range []string{"observed", "eligible_transit", "not_on_path_transit", "ambiguous_transit", "unavailable_transit", "unmapped_interface", "nontransit_interface"} {
		totals[name] = new(big.Int)
	}
	observed := map[int64]bool{}
	byTransit := map[string][]flow.PeeringTrafficFact{}
	var eligible []flow.PeeringTrafficFact
	for _, bucket := range traffic.Buckets {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		delta := bucket.Start.Sub(request.From)
		end := request.To
		if request.To.Sub(bucket.Start) > width {
			end = bucket.Start.Add(width)
		}
		value, valid := new(big.Int).SetString(bucket.Bytes, 10)
		flows, validFlows := new(big.Int).SetString(bucket.Flows, 10)
		if !valid || value.Sign() < 0 || value.String() != bucket.Bytes || !validFlows || flows.Sign() <= 0 || flows.String() != bucket.Flows || bucket.Start.Before(request.From) || !bucket.Start.Before(request.To) || delta%width != 0 || !bucket.End.Equal(end) {
			return none, apierror.Unavailable("peering traffic returned inconsistent observed intervals")
		}
		observed[int64(delta/width)] = true
		totals["observed"].Add(totals["observed"], value)
		name := "nontransit_interface"
		if bucket.InterfaceID == "" {
			name = "unmapped_interface"
			result.CompleteClassification = false
		} else if bucket.Role == entity.InterfaceRoleTransit {
			switch bucket.State {
			case "eligible", "not_on_path", "ambiguous", "unavailable":
			default:
				return none, apierror.Unavailable("peering traffic returned unknown path semantics")
			}
			name = bucket.State + "_transit"
			if bucket.State == "ambiguous" || bucket.State == "unavailable" {
				result.CompleteClassification = false
			}
			if _, exists := byTransit[bucket.InterfaceID]; !exists {
				byTransit[bucket.InterfaceID] = nil
			}
			if bucket.State == "eligible" {
				fact := flow.PeeringTrafficFact{TenantID: tenant.String(), Start: bucket.Start, Bytes: value}
				eligible = append(eligible, fact)
				byTransit[bucket.InterfaceID] = append(byTransit[bucket.InterfaceID], fact)
			}
		}
		totals[name].Add(totals[name], value)
	}
	for name, value := range totals {
		result.Bytes[name] = value.String()
	}
	result.ObservedIntervals = len(observed)
	result.CompleteObservedInputs = int64(len(observed)) == result.ExpectedIntervals
	if !result.CompleteObservedInputs {
		result.Reason = "missing_observed_intervals"
		return result, nil
	}
	if result.ExpectedIntervals > budget.MemoryBytes/4096 {
		return none, flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	complete := make([]time.Time, int(result.ExpectedIntervals))
	for i := range complete {
		complete[i] = request.From.Add(time.Duration(i) * width)
	}
	ids := make([]string, 0, len(byTransit))
	for id := range byTransit {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	window := flow.PeeringTrafficWindow{From: request.From, To: request.To, Interval: width, Complete: complete, MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.MemoryBytes / (4 * int64(len(ids)+1))}
	all, err := flow.EstimatePeeringTrafficRatesP95(ctx, window, eligible)
	if err != nil {
		return none, flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	result.P95 = &all
	for _, id := range ids {
		p95, err := flow.EstimatePeeringTrafficRatesP95(ctx, window, byTransit[id])
		if err != nil {
			return none, flowExplorerStoreError(flowstore.ErrExplorerBudget)
		}
		result.Transit = append(result.Transit, peeringTransitEstimate{InterfaceID: id, P95: p95})
	}
	result.Reason = "complete_observed_inputs"
	if !result.CompleteClassification {
		result.Reason = "partial_routing_evidence"
	}
	return result, nil
}
