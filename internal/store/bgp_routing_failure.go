// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPRoutingFailureNeighbor is one verified post-policy view. A view with no
// matching prefix contributes to evidence coverage without supplying a path.
type BGPRoutingFailureNeighbor struct {
	Peer, Local netip.Addr
	ASN         uint32
	Route       BGPRoutingLookup
}

type BGPRoutingFailureLookup struct {
	Selected  BGPRoutingLookup
	Neighbors []BGPRoutingFailureNeighbor
	// Complete means every observed peer was matched to one complete current
	// post-policy view. It makes no claim about unobserved router protocols.
	Complete bool
}

// BGPRoutingFailureCapture is the retained selected destination exit evidence
// for one flow in the requested context. It grants no use of a current route.
type BGPRoutingFailureCapture struct {
	Reference  entity.FlowCaptureReference
	Owner      InterfaceRoleFlowBinding
	View       BGPRoutingViewRef
	Prefix     netip.Prefix
	NextHops   []netip.Addr
	RouteBorn  time.Time
	RouteLease time.Time
}

func (BGPRouting) FailureCapturesInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, reads []flowstore.RoutingCaptureRead,
	budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) ([]BGPRoutingFailureCapture, error) {
	return readRoutingFailureCapturesInScope(ctx, sc, scope, reads, budget, authorize, false)
}

// TransferCapturesInScope returns retained route facts for a closed traffic
// window. A refreshed exporter observation qualifies only under a continuous
// current assignment. The original capture and routing sources stay authoritative.
func (BGPRouting) TransferCapturesInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, reads []flowstore.RoutingCaptureRead,
	budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) ([]BGPRoutingFailureCapture, error) {
	return readRoutingFailureCapturesInScope(ctx, sc, scope, reads, budget, authorize, true)
}

func readRoutingFailureCapturesInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, reads []flowstore.RoutingCaptureRead,
	budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error, continuousExporter bool) ([]BGPRoutingFailureCapture, error) {
	out := []BGPRoutingFailureCapture{}
	visit := func(ctx context.Context, read flowstore.RoutingCaptureRead, lookup BGPRoutingFlowLookup, admission *BGPRoutingBudget) error {
		if lookup.Owner.Scope != scope {
			return entity.ErrScopeMismatch
		}
		side := lookup.Destination
		if side.State != "router_selected" {
			return nil
		}
		route := side.Route
		if route.Source.Scope != scope || route.Source.RouterID != lookup.Owner.RouterID || !route.Prefix.Contains(read.Witness.Input.Destination.Unmap()) {
			return errRoutingCaptureFormat
		}
		record := BGPRoutingFailureCapture{Reference: read.Ref, Owner: lookup.Owner, View: route.View,
			Prefix: route.Prefix, RouteBorn: route.Source.ObservedAt, RouteLease: route.ValidUntil}
		for _, path := range route.Paths {
			if err := routingCaptureCountCharge(ctx, admission, len(path.NextHops), 256); err != nil {
				return err
			}
			record.NextHops = append(record.NextHops, path.NextHops...)
		}
		slices.SortFunc(record.NextHops, netip.Addr.Compare)
		record.NextHops = slices.Compact(record.NextHops)
		out = append(out, record)
		return ctx.Err()
	}
	visitor := routingCaptureVisitor{scope: scope, visit: visit, continuousExporter: continuousExporter}
	if _, err := readRoutingCaptureBatch(ctx, sc, reads, budget, authorize, &visitor); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

type bgpRoutingFailureView struct {
	ref         BGPRoutingViewRef
	born        time.Time
	peer, local netip.Addr
	asn         uint32
}

func isGlobalRoutingNeighbor(peer BGPRoutingPeer) bool {
	return peer.Type == 0 && peer.Distinguisher == [8]byte{} && peer.ASN != 0 && peer.SourceFormat == "" &&
		peer.BGPIdentifier.Is4() && peer.Address.IsValid() && peer.Address.Zone() == "" && !peer.Address.Is4In6() &&
		!peer.Address.IsUnspecified() && !peer.Address.IsMulticast()
}

// A global neighbor's BGP identifier names the peer, not the local router.
// Bind it only where the source already has one explicit global Loc-RIB
// assigned to its base router/context. Existing manifest authorization still
// checks the exact binding, credentials, assignment clocks and target birth.
func selectGlobalRoutingNeighbor(ctx context.Context, sc tenancy.Scope, config routingSourceConfiguration) (routingSourceSelection, error) {
	var selected *routingSourceBinding
	if config.Manifest != nil {
		for _, binding := range config.Manifest.Bindings {
			if err := ctx.Err(); err != nil {
				return routingSourceSelection{}, err
			}
			if binding.Distinguisher != "0000000000000000" || binding.ContextID != config.BaseContextID || binding.RouterID != config.BaseRouterID {
				continue
			}
			if selected != nil {
				return routingSourceSelection{}, errBGPRoutingContextBinding
			}
			selected = &binding
		}
	}
	if selected == nil {
		return routingSourceSelection{}, errBGPRoutingContextBinding
	}
	identifier, err := netip.ParseAddr(selected.BGPIdentifier)
	if err != nil || !identifier.Is4() {
		return routingSourceSelection{}, errBGPRoutingContextBinding
	}
	return selectRoutingSource(ctx, sc, config, BGPRoutingPeer{Type: 3, BGPIdentifier: identifier}, selected.Families)
}

// LookupRouterFailureInScope reads the selected view and post-policy alternatives
// from the same canonical router, context and authenticated BMP origin. The
// caller authorizes the requested router in this tenant read snapshot before
// making the lookup. The results are inputs to a read-only projection.
func (store BGPRouting) LookupRouterFailureInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, router string,
	address netip.Addr, budget BGPRoutingBudget) (BGPRoutingFailureLookup, error) {
	return store.lookupRouterAlternatesInScope(ctx, sc, scope, router, address, netip.Prefix{}, budget)
}

// LookupRouterPolicyPrefixInScope reads the selected and eligible routes for
// one exact NLRI. More-specific routes are independent of this policy selector.
// The caller authorizes the tenant and canonical router in the same snapshot.
func (store BGPRouting) LookupRouterPolicyPrefixInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, router string,
	prefix netip.Prefix, budget BGPRoutingBudget) (BGPRoutingFailureLookup, error) {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return BGPRoutingFailureLookup{}, ErrBGPRoutingView
	}
	return store.lookupRouterAlternatesInScope(ctx, sc, scope, router, prefix.Addr(), prefix, budget)
}

func (store BGPRouting) lookupRouterAlternatesInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, router string,
	address netip.Addr, exact netip.Prefix, budget BGPRoutingBudget) (BGPRoutingFailureLookup, error) {
	none := BGPRoutingFailureLookup{}
	if !address.IsValid() || address.Is4In6() || address.Zone() != "" {
		return none, ErrBGPRoutingView
	}
	portioned := budget
	portioned.MemoryBytes, portioned.WorkUnits = budget.MemoryBytes/3, budget.WorkUnits/3
	selected, err := store.lookupRouterScoped(ctx, sc, scope, router, address, exact, portioned)
	if err != nil {
		return none, err
	}
	out := BGPRoutingFailureLookup{Selected: selected}
	// An authenticated session down removes the peer from the expected set.
	// A monitoring withdrawal can hide a path that is still forwarding.
	peers, err := (&InterfaceRoleInputsStore{}).routerPeersInScope(ctx, sc, scope, router,
		entity.InterfaceRolePolicyBudget{MemoryBytes: portioned.MemoryBytes, WorkUnits: portioned.WorkUnits}, true)
	if err != nil {
		return none, err
	}
	afi := uint16(2)
	if address.Is4() {
		afi = 1
	}
	views, err := readBGPRoutingFailureViews(ctx, sc, selected.Source, afi, &portioned)
	if err != nil {
		return none, err
	}
	if len(views) == 0 {
		return out, nil
	}
	viewPopulation := map[netip.Addr]int{}
	for _, view := range views {
		viewPopulation[view.peer]++
	}
	perView := portioned
	perView.MemoryBytes /= int64(len(views))
	perView.WorkUnits /= int64(len(views))
	expected := map[netip.Addr]uint32{}
	complete := len(peers) != 0
	for _, peer := range peers {
		if current, present := expected[peer.Address]; present && current != peer.ASN {
			expected[peer.Address] = 0
			complete = false
		} else {
			expected[peer.Address] = peer.ASN
		}
	}
	covered := map[netip.Addr]bool{}
	for _, view := range views {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if !view.local.IsValid() || !view.peer.IsValid() || view.asn == 0 || view.asn != expected[view.peer] || viewPopulation[view.peer] != 1 {
			complete = false
			continue
		}
		source := selected.Source
		source.ObservedAt = view.born
		route, err := store.lookupCurrentRoutingViewInScope(ctx, sc, source, view.ref, address, exact, true, perView)
		if errors.Is(err, ErrBGPRoutingSourceUnavailable) {
			complete = false
			continue
		}
		if err != nil {
			return none, err
		}
		covered[view.peer] = true
		out.Neighbors = append(out.Neighbors, BGPRoutingFailureNeighbor{
			Peer: view.peer, Local: view.local, ASN: view.asn, Route: route,
		})
	}
	out.Complete = complete && len(expected) == len(covered)
	return out, ctx.Err()
}

func readBGPRoutingFailureViews(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, afi uint16, budget *BGPRoutingBudget) ([]bgpRoutingFailureView, error) {
	if err := routingBatchCharge(budget, 4096, 256); err != nil {
		return nil, err
	}
	selection, err := routingSelectionJSON(source)
	if err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT id::text,generation::text,observed_at,
 COALESCE(peer_identity->>'Address',''),COALESCE(peer_identity->>'LocalAddress',''),COALESCE(peer_identity->>'ASN','')
 FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3
 AND source_kind='router_bmp' AND view_kind='adj_rib_in_post_policy'
 AND collector_agent_id=$4 AND source_ref=$5 AND sender_serial=$6 AND origin_serial=$7
 AND afi=$8 AND safi=1 AND routing_selection IS NOT DISTINCT FROM $9::jsonb AND NOT filtered
 AND state='current' AND completed_at IS NOT NULL ORDER BY id LIMIT $10`,
		source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef,
		source.SenderSerial, source.OriginSerial, afi, selection, budget.MemoryBytes/4096+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []bgpRoutingFailureView{}
	for rows.Next() {
		if err := routingBatchCharge(budget, 4096, 512); err != nil {
			return nil, err
		}
		var view bgpRoutingFailureView
		var peer, local, asnText string
		if err := rows.Scan(&view.ref.ID, &view.ref.Generation, &view.born, &peer, &local, &asnText); err != nil {
			return nil, err
		}
		view.peer, view.local = failurePeerAddress(peer), failurePeerAddress(local)
		asn, err := strconv.ParseUint(asnText, 10, 32)
		if err == nil {
			view.asn = uint32(asn)
		}
		out = append(out, view)
	}
	return out, rows.Err()
}

func failurePeerAddress(text string) netip.Addr {
	address, err := netip.ParseAddr(text)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}
	}
	return address.Unmap()
}
