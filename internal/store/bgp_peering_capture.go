// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type BGPPeeringCaptureTarget struct {
	entity.Scope
	RouterID string
	PeerASN  uint32
}

// FlowPeeringCaptureProjectionsInScope uses the same immutable capture reader,
// current actor/source authorization and tenant RLS snapshot. Target selection
// is pushed into the header query before any payload is read. Empty results
// still require current access to the selected canonical context.
func (BGPRouting) FlowPeeringCaptureProjectionsInScope(ctx context.Context, sc tenancy.Scope, reads []flowstore.RoutingCaptureRead, target BGPPeeringCaptureTarget, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) ([]flowstore.RoutingProjection, error) {
	return readRoutingCaptureQueryBatchInScope(ctx, sc, reads, budget, authorize, target)
}

func validatePeeringCaptureTarget(ctx context.Context, sc tenancy.Scope, target BGPPeeringCaptureTarget) error {
	bound, present := tenancy.FromContext(ctx)
	scope, err := target.Normalize()
	if !present || bound != sc.Tenant || scope.TenantID != bound.String() || err != nil || scope != target.Scope || target.PeerASN == 0 {
		return entity.ErrScopeMismatch
	}
	if canonical, err := validRegistryUUID(target.RouterID); err != nil || canonical != target.RouterID {
		return entity.ErrScopeMismatch
	}
	return ctx.Err()
}

func routingCapturePeeringMatch(ctx context.Context, lookup BGPRoutingFlowLookup, target BGPPeeringCaptureTarget, budget *BGPRoutingBudget) (*flowstore.PeeringRoutingMatch, error) {
	if err := validatePeeringCaptureTarget(ctx, tenancy.Scope{Tenant: tenancy.ID(target.TenantID)}, target); err != nil {
		return nil, err
	}
	if lookup.Owner.Scope != target.Scope || lookup.Owner.RouterID != target.RouterID {
		return nil, entity.ErrScopeMismatch
	}
	if budget == nil {
		return nil, ErrBGPRoutingBudget
	}
	if err := routingBatchCharge(budget, 512, 512); err != nil {
		return nil, err
	}
	match := &flowstore.PeeringRoutingMatch{RouterID: target.RouterID, PeerASN: target.PeerASN}
	for i, side := range []BGPRoutingFlowSide{lookup.Source, lookup.Destination} {
		value, err := routingCapturePeeringSide(ctx, side, target.PeerASN, budget)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			match.Source = value.State
		} else {
			match.Destination = value.State
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return match, nil
}

func routingCapturePeeringSide(ctx context.Context, side BGPRoutingFlowSide, peer uint32, budget *BGPRoutingBudget) (bgp.PeeringPathMatch, error) {
	if err := ctx.Err(); err != nil {
		return bgp.PeeringPathMatch{}, err
	}
	var changes []BGPRoutingChange
	switch side.State {
	case "no_prefix", "public_no_prefix":
		return bgp.PeeringPathMatch{State: bgp.PeeringPathNotOnPath}, nil
	case "source_unavailable":
		return bgp.PeeringPathMatch{State: bgp.PeeringPathUnavailable}, nil
	case "router_selected":
		changes = side.Route.Paths
	case "public_fallback":
		if side.Public == nil {
			return bgp.PeeringPathMatch{}, errRoutingCaptureFormat
		}
		if err := routingCaptureCountCharge(ctx, budget, len(side.Public.Paths), 512); err != nil {
			return bgp.PeeringPathMatch{}, err
		}
		changes = make([]BGPRoutingChange, len(side.Public.Paths))
		for i, path := range side.Public.Paths {
			changes[i] = path.Path
		}
	default:
		return bgp.PeeringPathMatch{}, errRoutingCaptureFormat
	}
	if len(changes) == 0 {
		return bgp.PeeringPathMatch{}, errRoutingCaptureFormat
	}
	workBefore := budget.WorkUnits
	if err := routingCaptureCountCharge(ctx, budget, len(changes), 128); err != nil {
		return bgp.PeeringPathMatch{}, err
	}
	paths := make([][]bgp.ASPathSegment, len(changes))
	for i, path := range changes {
		if err := routingCaptureCountCharge(ctx, budget, len(path.Segments), 128); err != nil {
			return bgp.PeeringPathMatch{}, err
		}
		paths[i] = make([]bgp.ASPathSegment, len(path.Segments))
		for j, segment := range path.Segments {
			if err := routingCaptureCountCharge(ctx, budget, len(segment.Values), 8); err != nil {
				return bgp.PeeringPathMatch{}, err
			}
			// Values belong to this immutable request-local lookup. Matching
			// reads their full typed semantics without reparsing display text.
			paths[i][j] = bgp.ASPathSegment{Kind: bgp.ASPathSegmentKind(segment.Kind), Values: segment.Values}
		}
	}
	return bgp.MatchPeeringPaths(ctx, peer, paths, bgp.ASPathParseBudget{MemoryBytes: 128, WorkUnits: workBefore - budget.WorkUnits})
}
