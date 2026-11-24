// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type topologyFailureRouteKey struct {
	router      string
	destination netip.Addr
}

type topologyFailureRoute struct {
	evidence flow.FailureRouteEvidence
	exits    map[netip.Addr][]flow.FailurePort
	original store.BGPRoutingFailureLookup
}

type topologyFailureRouting struct {
	captures map[[32]byte]store.BGPRoutingFailureCapture
	routes   map[topologyFailureRouteKey]topologyFailureRoute
}

// readTopologyFailureRouting binds current route eligibility to current device
// evidence and preserves the separate source proof of each original flow.
func (s *Server) readTopologyFailureRouting(ctx context.Context, actor *auth.Principal, scope entity.Scope,
	sources topologyFailureSourcePlan, reads []flowstore.RoutingCaptureRead, budget flowstore.ExplorerBudget) (topologyFailureRouting, error) {
	out := topologyFailureRouting{captures: map[[32]byte]store.BGPRoutingFailureCapture{}, routes: map[topologyFailureRouteKey]topologyFailureRoute{}}
	err := s.withTopologyFailureSnapshot(ctx, actor, scope, budget, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		const partition = 4
		bgpBudget := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / partition, WorkUnits: budget.ReadBytes / partition, StateBytes: budget.MemoryBytes}
		routing := store.BGPRouting{}
		captures, err := routing.FailureCapturesInScope(ctx, sc, scope, reads, bgpBudget, func(ctx context.Context, current entity.ContextRecord) error {
			return authorize(ctx, current, "")
		})
		if err != nil {
			return err
		}
		for _, capture := range captures {
			if err := authorize(ctx, record, capture.Owner.RouterID); err != nil {
				return err
			}
			out.captures[capture.Reference.Key] = capture
		}
		targets := map[topologyFailureRouteKey]bool{}
		for _, read := range reads {
			capture, ok := out.captures[read.Ref.Key]
			if ok {
				targets[topologyFailureRouteKey{capture.Owner.RouterID, read.Witness.Input.Destination.Unmap()}] = true
			}
		}
		if len(targets) == 0 {
			return ctx.Err()
		}
		bgpBudget.MemoryBytes /= int64(len(targets))
		bgpBudget.WorkUnits /= int64(len(targets))
		index := map[string][]topologyFailureLink{}
		for _, link := range sources.links {
			if link.port.InterfaceID != "" {
				index[link.port.InterfaceID] = append(index[link.port.InterfaceID], link)
			}
		}
		resolver := topologyFailureNeighborResolver{counters: store.NewDeviceCounterCaptures(s.pool), scope: scope, byInterface: index,
			addresses: map[topologyFailureRouteKey]string{}}
		for key := range targets {
			view, err := routing.LookupRouterFailureInScope(ctx, sc, scope, key.router, key.destination, bgpBudget)
			if errors.Is(err, store.ErrBGPRoutingSourceUnavailable) || errors.Is(err, store.ErrBGPRoutingRouteMissing) || errors.Is(err, store.ErrBGPRoutingAmbiguousView) {
				continue
			}
			if err != nil {
				return err
			}
			route := topologyFailureRoute{original: view, exits: map[netip.Addr][]flow.FailurePort{}}
			route.evidence.EligibleComplete = view.Complete
			for _, neighbor := range view.Neighbors {
				path, err := resolver.exit(ctx, sc, key.router, neighbor)
				if err != nil {
					return err
				}
				if len(path) > 0 {
					route.exits[neighbor.Peer] = path
				}
				for _, candidate := range neighbor.Route.Paths {
					var via []flow.FailurePort
					if slices.Contains(candidate.NextHops, neighbor.Peer) {
						via = path
					}
					route.evidence.Eligible = append(route.evidence.Eligible, flow.FailureRouteCandidate{Prefix: candidate.Prefix, Ports: via})
				}
			}
			for _, path := range view.Selected.Paths {
				route.evidence.Selected = append(route.evidence.Selected, flow.FailureRouteCandidate{
					Prefix: path.Prefix, Ports: topologySelectedFailurePath(path.NextHops, route.exits),
				})
			}
			out.routes[key] = route
		}
		return ctx.Err()
	})
	if err != nil {
		return topologyFailureRouting{}, err
	}
	return out, ctx.Err()
}

func topologySelectedFailurePath(hops []netip.Addr, exits map[netip.Addr][]flow.FailurePort) []flow.FailurePort {
	var path []flow.FailurePort
	for _, hop := range hops {
		candidate := exits[hop]
		if len(candidate) == 0 && hop.IsLinkLocalUnicast() {
			continue // MP_REACH can carry an auxiliary link-local address.
		}
		if len(candidate) == 0 || len(path) > 0 && !slices.Equal(path, candidate) {
			return nil
		}
		path = candidate
	}
	return path
}

type topologyFailureNeighborResolver struct {
	counters    *store.DeviceCounterCaptures
	scope       entity.Scope
	byInterface map[string][]topologyFailureLink
	addresses   map[topologyFailureRouteKey]string
}

func (resolver *topologyFailureNeighborResolver) interfaceAt(ctx context.Context, sc tenancy.Scope, device string, address netip.Addr) (string, error) {
	key := topologyFailureRouteKey{device, address}
	if id, read := resolver.addresses[key]; read {
		return id, nil
	}
	id, err := resolver.counters.CurrentAddressInterfaceInScope(ctx, sc, resolver.scope, device, address.String())
	if err == nil {
		resolver.addresses[key] = id
	}
	return id, err
}

func (resolver *topologyFailureNeighborResolver) exit(ctx context.Context, sc tenancy.Scope, router string, neighbor store.BGPRoutingFailureNeighbor) ([]flow.FailurePort, error) {
	id, err := resolver.interfaceAt(ctx, sc, router, neighbor.Local)
	if err != nil {
		return nil, err
	}
	a, ok := uniqueTopologyFailureLink(resolver.byInterface[id])
	if !ok || a.fromDevice != router {
		return nil, nil
	}
	remoteID, err := resolver.interfaceAt(ctx, sc, a.original.ToEntityID, neighbor.Peer)
	if err != nil {
		return nil, err
	}
	b, ok := uniqueTopologyFailureLink(resolver.byInterface[remoteID])
	if !ok {
		return nil, nil
	}
	if a.fromDevice != b.original.ToEntityID || a.original.ToEntityID != b.fromDevice ||
		a.original.LocalPort == "" || a.original.RemotePort == "" ||
		a.original.LocalPort != b.original.RemotePort || a.original.RemotePort != b.original.LocalPort {
		return nil, nil
	}
	return []flow.FailurePort{{InterfaceID: id, Direction: "out"}, {InterfaceID: remoteID, Direction: "in"}}, nil
}

func uniqueTopologyFailureLink(links []topologyFailureLink) (topologyFailureLink, bool) {
	if len(links) == 0 {
		return topologyFailureLink{}, false
	}
	first := links[0].original
	for _, link := range links[1:] {
		other := link.original
		if first.FromEntityID != other.FromEntityID || first.ToEntityID != other.ToEntityID ||
			first.LocalIfIndex != other.LocalIfIndex || first.LocalPort != other.LocalPort || first.RemotePort != other.RemotePort {
			return topologyFailureLink{}, false
		}
	}
	return links[0], true
}
