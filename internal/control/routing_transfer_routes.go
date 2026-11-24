// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingTransferPorts struct {
	source, candidate store.DeviceCounterInterface
}

type routingTransferRoute struct {
	prefix                 netip.Prefix
	selected               netip.Addr
	candidate              netip.Addr
	candidateASN           uint32
	selectedView           store.BGPRoutingViewRef
	candidateView          store.BGPRoutingViewRef
	validUntil             time.Time
	highestKnownPreference uint32
	pathsFingerprint       [32]byte
}

func selectRoutingTransferPorts(scope entity.Scope, plans routingTransferBillPlans) routingTransferPorts {
	var ports routingTransferPorts
	for _, member := range plans.plan[0].members {
		if member.target.Scope == scope && member.target.InterfaceID == plans.selection[0].EgressID {
			ports.source = member.target
			break
		}
	}
	for _, member := range plans.plan[1].members {
		if member.target.Scope == scope && member.target.InterfaceID == plans.selection[1].EgressID {
			ports.candidate = member.target
			break
		}
	}
	return ports
}

// authorizeRoutingTransferRoute binds an exact announcement to the two local
// handoffs of one operator-owned router. A transit peer's remote interface does
// not need to be instrumented to verify a local egress assignment.
func (s *Server) authorizeRoutingTransferRoute(ctx context.Context, actor *auth.Principal, scope entity.Scope,
	ports routingTransferPorts, prefix netip.Prefix, budget flowstore.ExplorerBudget) (routingTransferRoute, error) {
	var out routingTransferRoute
	router := ports.source.Source.DeviceID
	if ports.source.Scope != scope || ports.candidate.Scope != scope || router == "" || router != ports.candidate.Source.DeviceID {
		return out, apierror.Validation("the handoffs must belong to the same verified routing device and context")
	}
	err := s.withTopologyFailureSnapshot(ctx, actor, scope, budget, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		for _, id := range []string{router, ports.source.InterfaceID, ports.candidate.InterfaceID} {
			if err := authorize(ctx, record, id); err != nil {
				return err
			}
		}
		bgpBudget := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.ReadBytes / 8, StateBytes: budget.MemoryBytes}
		view, err := (store.BGPRouting{}).LookupRouterPolicyPrefixInScope(ctx, sc, scope, router, prefix, bgpBudget)
		if err != nil {
			return err
		}
		if !view.Complete || view.Selected.Prefix != prefix || len(view.Selected.Paths) != 1 {
			return apierror.Unavailable("the exact prefix lacks one selected path and complete upstream evidence")
		}
		selected := singleRoutingTransferNextHop(view.Selected.Paths[0].NextHops)
		if !selected.IsValid() {
			return apierror.Unavailable("the selected path has no unique physical next hop")
		}
		reader := store.NewDeviceCounterCaptures(s.pool)
		result, err := chooseRoutingTransferHandoffs(ctx, sc, scope, reader, ports, prefix, view, selected)
		if err != nil {
			return err
		}
		out = result
		return ctx.Err()
	})
	if err != nil {
		return routingTransferRoute{}, err
	}
	return out, ctx.Err()
}

func chooseRoutingTransferHandoffs(ctx context.Context, sc tenancy.Scope, scope entity.Scope,
	reader *store.DeviceCounterCaptures, ports routingTransferPorts, prefix netip.Prefix,
	view store.BGPRoutingFailureLookup, selected netip.Addr) (routingTransferRoute, error) {
	var out routingTransferRoute
	router := ports.source.Source.DeviceID
	var currentPresent bool
	var candidatePath store.BGPRoutingChange
	out.validUntil = view.Selected.ValidUntil
	out.highestKnownPreference = routingTransferLocalPreference(view.Selected.Paths[0])
	for _, neighbor := range view.Neighbors {
		if err := ctx.Err(); err != nil {
			return routingTransferRoute{}, err
		}
		if neighbor.Route.Prefix != prefix || len(neighbor.Route.Paths) != 1 ||
			!slices.Contains(neighbor.Route.Paths[0].NextHops, neighbor.Peer) {
			continue
		}
		out.highestKnownPreference = max(out.highestKnownPreference, routingTransferLocalPreference(neighbor.Route.Paths[0]))
		id, err := reader.CurrentAddressInterfaceInScope(ctx, sc, scope, router, neighbor.Local.String())
		if err != nil {
			return routingTransferRoute{}, err
		}
		switch {
		case neighbor.Peer == selected && id == ports.source.InterfaceID:
			currentPresent = true
		case neighbor.Peer != selected && id == ports.candidate.InterfaceID:
			if out.candidate.IsValid() {
				return routingTransferRoute{}, apierror.Unavailable("more than one eligible route uses the candidate handoff")
			}
			candidatePath = neighbor.Route.Paths[0]
			out.candidate, out.candidateASN, out.candidateView = neighbor.Peer, neighbor.ASN, neighbor.Route.View
		default:
			continue
		}
		if neighbor.Route.ValidUntil.Before(out.validUntil) {
			out.validUntil = neighbor.Route.ValidUntil
		}
	}
	if !currentPresent || !out.candidate.IsValid() {
		return routingTransferRoute{}, apierror.Unavailable("the exact route does not bind both selected physical handoffs")
	}
	paths, err := json.Marshal([2]store.BGPRoutingChange{view.Selected.Paths[0], candidatePath})
	if err != nil {
		return routingTransferRoute{}, err
	}
	copy(out.pathsFingerprint[:], crypto.Hash(paths))
	out.prefix, out.selected, out.selectedView = prefix, selected, view.Selected.View
	return out, nil
}

func singleRoutingTransferNextHop(nextHops []netip.Addr) netip.Addr {
	var selected netip.Addr
	for _, hop := range nextHops {
		if hop.IsLinkLocalUnicast() {
			continue // auxiliary link-local next hop may accompany IPv6 MP_REACH
		}
		if !hop.IsValid() || hop.IsUnspecified() || hop.Zone() != "" || selected.IsValid() && hop.Unmap() != selected {
			return netip.Addr{}
		}
		selected = hop.Unmap()
	}
	return selected
}

// LOCAL_PREF can be absent from a peer's original path. Compare only recorded
// values. The operator review must verify effective router policy and defaults.
func routingTransferLocalPreference(path store.BGPRoutingChange) uint32 {
	for _, attribute := range path.Attributes.Wire {
		if attribute.Type == 5 && len(attribute.Value) == 4 {
			return binary.BigEndian.Uint32(attribute.Value)
		}
	}
	return 0
}
