// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"math/big"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const topologyFailureInterval = 5 * time.Minute

type topologyFailureProjection struct {
	series       flow.FailureTrafficSeries
	unattributed int
}

func projectTopologyFailure(ctx context.Context, scope entity.Scope, target topologyFailureTarget, flows topologyFailureFlows,
	routes topologyFailureRouting, counters topologyFailureCounters, from, to, until time.Time, budget flowstore.ExplorerBudget) (topologyFailureProjection, error) {
	none := topologyFailureProjection{}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != scope.TenantID {
		return none, tenancy.ErrNoTenant
	}
	span := to.Sub(from)
	if from.IsZero() || span <= 0 || !from.Add(span).Equal(to) {
		return none, flow.ErrFailureTrafficInput
	}
	count := int64(1 + (span-1)/topologyFailureInterval)
	if count > budget.MemoryBytes/4096 || count > budget.ReadBytes/4096 {
		return none, flow.ErrFailureTrafficBudget
	}
	samples := make([]flow.FailureTrafficSample, int(count))
	for i := range samples {
		start := from.Add(time.Duration(i) * topologyFailureInterval)
		samples[i] = flow.FailureTrafficSample{TenantID: scope.TenantID, From: start, To: start.Add(min(topologyFailureInterval, to.Sub(start))),
			DemandComplete: flows.complete, Failed: target.ports}
	}
	if err := loadTopologyFailureBaselines(ctx, samples, counters, budget.MemoryBytes/4); err != nil {
		return none, err
	}
	broken := make(map[flow.FailurePort]bool, len(target.ports))
	for _, port := range target.ports {
		broken[port] = true
	}
	remaining := min(budget.MemoryBytes/4, budget.ReadBytes/4)
	seen := map[[32]byte]bool{}
	out := topologyFailureProjection{}
	for _, row := range flows.rows {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if row.TenantID != scope.TenantID {
			return none, tenancy.ErrNoTenant
		}
		key, err := topologyFailureCaptureKey(row.RoutingCaptureKey)
		if err != nil {
			return none, err
		}
		capture, captured := routes.captures[key]
		if !captured {
			out.unattributed++
			continue
		}
		if seen[key] {
			continue // one signed original in this measurement population
		}
		if remaining < 128 {
			return none, flow.ErrFailureTrafficBudget
		}
		remaining -= 128
		seen[key] = true
		demand, valid, err := topologyFailureDemand(ctx, row, capture, flows, routes, broken)
		if err != nil {
			return none, err
		}
		if !valid {
			out.unattributed++
			continue
		}
		if err := distributeTopologyFailureFlow(ctx, samples, row, demand, &remaining); err != nil {
			return none, err
		}
	}
	for i := range samples {
		samples[i].DemandComplete = samples[i].DemandComplete && out.unattributed == 0
	}
	series, err := flow.ProjectFailureTrafficSeries(ctx, samples, until, budget.MemoryBytes/2, budget.ReadBytes/2)
	if err != nil {
		return none, err
	}
	out.series = series
	return out, ctx.Err()
}

func loadTopologyFailureBaselines(ctx context.Context, samples []flow.FailureTrafficSample, counters topologyFailureCounters, memory int64) error {
	if int64(len(counters.plan.members)) > memory/int64(len(samples))/2048 {
		return flow.ErrFailureTrafficBudget
	}
	members := map[string]flow.CapacityMeasuredMember{}
	for _, member := range counters.members {
		members[member.Source().InterfaceID] = member
	}
	for _, item := range counters.plan.members {
		id := item.target.InterfaceID
		member := members[id]
		for _, direction := range []string{"in", "out"} {
			grid := member.Samples(direction)
			for i := range samples {
				if err := ctx.Err(); err != nil {
					return err
				}
				base := flow.FailureTrafficBaseline{FailurePort: flow.FailurePort{InterfaceID: id, Direction: direction}, CapacityBPS: item.maximum}
				if len(grid) != 0 {
					if i >= len(grid) || !grid[i].From.Equal(samples[i].From) || !grid[i].To.Equal(samples[i].To) {
						return flow.ErrFailureTrafficInput
					}
					if grid[i].Observed {
						value, ok := new(big.Rat).SetString(grid[i].BPSNumerator + "/" + grid[i].BPSDenominator)
						if !ok || value.Sign() < 0 {
							return flow.ErrFailureTrafficInput
						}
						base.BPS = value
					}
				}
				samples[i].Baselines = append(samples[i].Baselines, base)
			}
		}
	}
	return nil
}

func topologyFailureCaptureKey(text string) ([32]byte, error) {
	var key [32]byte
	if text == "" {
		return key, nil
	}
	if len(text) != hex.EncodedLen(len(key)) {
		return key, flow.ErrFailureTrafficInput
	}
	_, err := hex.Decode(key[:], []byte(text))
	return key, err
}

func topologyFailureDemand(ctx context.Context, row flowstore.Row, capture store.BGPRoutingFailureCapture,
	flows topologyFailureFlows, routes topologyFailureRouting, broken map[flow.FailurePort]bool) (flow.FailureTrafficDemand, bool, error) {
	none := flow.FailureTrafficDemand{}
	if capture.Owner.TenantID != row.TenantID {
		return none, false, tenancy.ErrNoTenant
	}
	switch row.ClockBasis {
	case flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL:
		if !row.TS.After(row.StartTS) || row.Protocol == flow.ProtoSFlow5 {
			return none, false, nil
		}
	case flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_COLLECTOR_SAMPLE:
		if !row.TS.Equal(row.StartTS) || row.Protocol != flow.ProtoSFlow5 {
			return none, false, nil
		}
	default:
		return none, false, nil
	}
	// A routing heartbeat advances the view clock without changing the
	// observed egress. The exporter interval and exact out-if establish the
	// original demand, and the capture corroborates its selected route.
	if row.StartTS.UnixNano() <= 0 || row.StartTS.Before(capture.RouteBorn) ||
		row.TS.After(capture.Reference.CapturedAt) || !capture.RouteLease.After(capture.Reference.CapturedAt) || row.Sampling == 0 {
		return none, false, nil
	}
	port := flow.FailurePort{InterfaceID: flows.ports[topologyFailureInterfaceKey{capture.Owner.RouterID, row.OutIf}], Direction: "out"}
	if !broken[port] {
		return none, false, entity.ErrScopeMismatch
	}
	dst, err := netip.ParseAddr(row.DstAddr)
	if err != nil || dst.Zone() != "" || !capture.Prefix.Contains(dst.Unmap()) {
		return none, false, flow.ErrFailureTrafficInput
	}
	unresolved := flow.FailureTrafficDemand{Before: []flow.FailurePort{port}, Disposition: flow.FailureTrafficUnresolved}
	route := routes.routes[topologyFailureRouteKey{capture.Owner.RouterID, dst.Unmap()}]
	var reported netip.Addr
	if row.NextHop != "" {
		reported, err = netip.ParseAddr(row.NextHop)
		if err != nil || reported.Zone() != "" {
			return unresolved, true, nil
		}
	}
	var before []flow.FailurePort
	for _, hop := range capture.NextHops {
		path := route.exits[hop.Unmap()]
		if (reported.IsValid() && !reported.IsUnspecified() && reported.Unmap() != hop.Unmap()) || len(path) == 0 || path[0] != port {
			continue
		}
		if len(before) > 0 && !slices.Equal(before, path) {
			return unresolved, true, nil
		}
		before = path
	}
	if len(before) == 0 || !slices.ContainsFunc(route.evidence.Selected, func(candidate flow.FailureRouteCandidate) bool {
		return candidate.Prefix == capture.Prefix && slices.Equal(candidate.Ports, before)
	}) {
		return unresolved, true, nil
	}
	disposition, after, err := flow.ChooseFailureTrafficRoute(ctx, dst.Unmap(), before, broken, route.evidence)
	return flow.FailureTrafficDemand{Before: before, After: after, Disposition: disposition}, err == nil, err
}

// distributeTopologyFailureFlow applies the stated mean-overlap model to an
// original interval. Instantaneous samples contribute to their observed bin.
func distributeTopologyFailureFlow(ctx context.Context, samples []flow.FailureTrafficSample, row flowstore.Row,
	demand flow.FailureTrafficDemand, remaining *int64) error {
	return walkTopologyFlowRates(ctx, samples[0].From, samples[len(samples)-1].To, row, remaining, func(i int, rate *big.Rat) error {
		item := demand
		item.BPS = rate
		samples[i].Demands = append(samples[i].Demands, item)
		return nil
	})
}

// walkTopologyFlowRates keeps the exporter interval's exact mean-overlap
// distribution shared by failure and routing-move estimates.
func walkTopologyFlowRates(ctx context.Context, from, to time.Time, row flowstore.Row, remaining *int64, visit func(int, *big.Rat) error) error {
	instant := row.StartTS.Equal(row.TS)
	start, end := laterFailureTime(row.StartTS, from), earlierFailureTime(row.TS, to)
	if !start.Before(to) || instant && row.TS.Before(from) || !instant && !end.After(start) || row.Bytes == 0 {
		return nil
	}
	span := row.TS.Sub(row.StartTS)
	if !instant && (span <= 0 || !row.StartTS.Add(span).Equal(row.TS)) {
		return flow.ErrFailureTrafficInput
	}
	scaled := new(big.Int).Mul(new(big.Int).SetUint64(row.Bytes), new(big.Int).SetUint64(row.Sampling))
	first := int(start.Sub(from) / topologyFailureInterval)
	for i, left := first, from.Add(time.Duration(first)*topologyFailureInterval); left.Before(to); i, left = i+1, left.Add(topologyFailureInterval) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !instant && !left.Before(end) {
			break
		}
		if *remaining < 1024 {
			return flow.ErrFailureTrafficBudget
		}
		*remaining -= 1024
		right := left.Add(min(topologyFailureInterval, to.Sub(left)))
		rate := new(big.Rat).SetInt(scaled)
		if !instant {
			overlap := earlierFailureTime(end, right).Sub(laterFailureTime(start, left))
			rate.Mul(rate, big.NewRat(int64(overlap), int64(span)))
		}
		rate.Mul(rate, big.NewRat(8_000_000_000, int64(right.Sub(left))))
		if err := visit(i, rate); err != nil {
			return err
		}
		if instant {
			break
		}
	}
	return ctx.Err()
}

func laterFailureTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlierFailureTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
