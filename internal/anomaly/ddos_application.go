// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"math"
	"math/big"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DDoSApplicationWindow is one independent, bounded server observation.
// The authenticated tenant, application binding and exact flow clock must
// be checked before it can qualify an inferred flash crowd.
type DDoSApplicationWindow struct {
	TenantID          string        `json:"-"`
	Target            netip.Prefix  `json:"-"`
	From              time.Time     `json:"from"`
	To                time.Time     `json:"to"`
	Requests          int           `json:"observed_requests"`
	Successes         int           `json:"successful_requests"`
	P95               time.Duration `json:"p95_nanos,string"`
	Digest            string        `json:"observation_digest"`
	FlowBytes         string        `json:"matching_flow_bytes"`
	FlowPackets       string        `json:"matching_flow_packets"`
	SamplingThreshold string        `json:"-"`
}

type DDoSApplicationEvidence struct {
	Reference DDoSApplicationWindow `json:"reference"`
	Current   DDoSApplicationWindow `json:"current"`
	State     string                `json:"state"`
}

const (
	DDoSApplicationObserved  = "observed_application_demand"
	DDoSApplicationDegraded  = "application_health_degraded"
	DDoSApplicationDemand    = "traffic_growth_explained_by_healthy_application_demand"
	DDoSApplicationAmbiguous = "application_demand_does_not_explain_all_traffic"
	DDoSApplicationResidual  = "traffic_outside_bound_application_exceeds_threshold"
	DDoSApplicationSampling  = "application_trace_sampling_incomparable"
	DDoSSamplingMixed        = "mixed"
)

// QualifyDDoSApplication compares independently observed successful requests
// to both byte and packet growth. Healthy service alone cannot suppress flow
// pressure, and explicit network vectors retain their original evidence.
func QualifyDDoSApplication(ctx context.Context, reference, current DDoSObservation, earlier, latest DDoSApplicationWindow,
	finding *DDoSDetection, limits DDoSThresholds, work int64) (*DDoSDetection, *DDoSApplicationEvidence, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, nil, ErrNoTenant
	}
	if reference.TenantID != tenant.String() || current.TenantID != tenant.String() ||
		earlier.TenantID != tenant.String() || latest.TenantID != tenant.String() {
		return nil, nil, ErrCrossTenantFeature
	}
	if err := checkDDoSWindows(ctx, reference, current); err != nil {
		return nil, nil, err
	}
	if !validDDoSAppWindow(earlier, reference) || !validDDoSAppWindow(latest, current) {
		return finding, nil, ctx.Err()
	}
	earlier.FlowBytes, earlier.FlowPackets = reference.ApplicationBytes, reference.ApplicationPackets
	latest.FlowBytes, latest.FlowPackets = current.ApplicationBytes, current.ApplicationPackets
	proof := &DDoSApplicationEvidence{Reference: earlier, Current: latest, State: DDoSApplicationObserved}
	if finding == nil || finding.Class != DDoSVolumetric {
		return finding, proof, ctx.Err()
	}
	parser := decimalSeasonalTraining{work: work}
	requests := [2]int{earlier.Successes, latest.Successes}
	bytes, err := compareApplicationTraffic(&parser, requests, reference.Bytes, current.Bytes,
		reference.ApplicationBytes, current.ApplicationBytes, limits.BytesFloor, limits.GrowthBasisPoints)
	if err != nil {
		return nil, nil, err
	}
	packets, err := compareApplicationTraffic(&parser, requests, reference.Packets, current.Packets,
		reference.ApplicationPackets, current.ApplicationPackets, limits.PacketsFloor, limits.GrowthBasisPoints)
	if err != nil {
		return nil, nil, err
	}
	listenerPressure := bytes.listenerPressure || packets.listenerPressure
	degraded := !withinDDoSApplicationErrorBudget(latest) || latest.P95-earlier.P95 > earlier.P95/2
	switch {
	case bytes.residualPressure || packets.residualPressure:
		proof.State = DDoSApplicationResidual
	case !withinDDoSApplicationErrorBudget(earlier):
		proof.State = DDoSApplicationAmbiguous
	case earlier.SamplingThreshold != latest.SamplingThreshold || earlier.SamplingThreshold == DDoSSamplingMixed:
		proof.State = DDoSApplicationSampling
	case degraded && listenerPressure:
		proof.State = DDoSApplicationDegraded
	case degraded:
		// Application failure without independently qualifying listener
		// traffic cannot corroborate aggregate traffic on the protected host.
		proof.State = DDoSApplicationAmbiguous
	case latest.Successes <= earlier.Successes && listenerPressure:
		proof.State = DDoSApplicationObserved
	case bytes.explained && packets.explained:
		proof.State = DDoSApplicationDemand
		finding = nil
	default:
		proof.State = DDoSApplicationAmbiguous
	}
	return finding, proof, ctx.Err()
}

type applicationTrafficComparison struct {
	explained, listenerPressure, residualPressure bool
}

// A falling listener can hide independent pressure from the host-wide totals.
// This precheck uses only L4 counters. The caller still qualifies the finding
// against the independently observed application windows before an episode.
func outsideDDoSApplicationPressure(parser *decimalSeasonalTraining, reference, current DDoSObservation, limits DDoSThresholds) (bool, error) {
	width := current.To.Sub(current.From)
	if (width != 5*time.Second && width != 10*time.Second) || current.Direction != "ingress" || !current.Target.IsSingleIP() ||
		reference.ApplicationBytes == "" || current.ApplicationBytes == "" || reference.ApplicationPackets == "" || current.ApplicationPackets == "" {
		return false, nil
	}
	bytes, err := compareApplicationTraffic(parser, [2]int{}, reference.Bytes, current.Bytes,
		reference.ApplicationBytes, current.ApplicationBytes, limits.BytesFloor, limits.GrowthBasisPoints)
	if err != nil {
		return false, err
	}
	packets, err := compareApplicationTraffic(parser, [2]int{}, reference.Packets, current.Packets,
		reference.ApplicationPackets, current.ApplicationPackets, limits.PacketsFloor, limits.GrowthBasisPoints)
	return bytes.residualPressure || packets.residualPressure, err
}

func compareApplicationTraffic(parser *decimalSeasonalTraining, requests [2]int,
	reference, current, referenceApplication, currentApplication, configuredFloor string, growth int) (applicationTrafficComparison, error) {
	var values [5]*big.Rat
	for i, counter := range []string{reference, current, referenceApplication, currentApplication, configuredFloor} {
		value, err := ddosCounter(parser, counter)
		if err != nil {
			return applicationTrafficComparison{}, err
		}
		values[i] = value
	}
	before, after, appBefore, appAfter, floor := values[0], values[1], values[2], values[3], values[4]
	if appBefore.Cmp(before) > 0 || appAfter.Cmp(after) > 0 {
		return applicationTrafficComparison{}, ErrDDoSCoverage
	}
	residualBefore := new(big.Rat).Sub(before, appBefore)
	residualAfter := new(big.Rat).Sub(after, appAfter)
	return applicationTrafficComparison{
		explained: comparableDDoSDemand(appBefore, appAfter, requests[0], requests[1]) &&
			(residualAfter.Cmp(residualBefore) <= 0 || comparableDDoSDemand(before, after, requests[0], requests[1])),
		listenerPressure: exceedsDDoSVolume(appAfter, appBefore, floor, growth),
		residualPressure: exceedsDDoSVolume(residualAfter, residualBefore, floor, growth),
	}, nil
}

func validDDoSAppWindow(app DDoSApplicationWindow, flow DDoSObservation) bool {
	return flow.Direction == "ingress" && flow.Target == app.Target && app.Target.IsSingleIP() &&
		app.From.Equal(flow.From) && app.To.Equal(flow.To) &&
		app.Requests >= 20 && app.Requests <= math.MaxInt/125 && app.Successes >= 0 && app.Successes <= app.Requests &&
		app.P95 > 0 && len(app.Digest) == 64
}

func withinDDoSApplicationErrorBudget(app DDoSApplicationWindow) bool {
	const errorBudgetPercent = 1
	return (app.Requests-app.Successes)*100 <= app.Requests*errorBudgetPercent
}

// Compare growth ratios without rounding or converting window counters to
// floating point. The successful-request growth must explain both counters.
func comparableDDoSDemand(before, after *big.Rat, previous, current int) bool {
	if before.Sign() <= 0 || after.Cmp(before) <= 0 || previous <= 0 {
		return false
	}
	actual := new(big.Rat).Mul(after, big.NewRat(100*int64(previous), 1))
	low := new(big.Rat).Mul(before, big.NewRat(75*int64(current), 1))
	high := new(big.Rat).Mul(before, big.NewRat(125*int64(current), 1))
	return actual.Cmp(low) >= 0 && actual.Cmp(high) <= 0
}
