// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type BGPRPKICurrentPrefix struct {
	BGPRoutingLookup
	PathFields []bgp.RoutingPathFields
}

// CurrentBGPRPKIPrefixInScope joins the verified history source to its still
// current, complete exact-prefix population. History authorizes which source
// can be read. The current view determines whether the route remains present.
func CurrentBGPRPKIPrefixInScope(ctx context.Context, sc tenancy.Scope, prefix netip.Prefix, original BGPASPathHistoryRecord,
	budget BGPRoutingBudget, authorize RoutingChangeAuthorizer) (BGPRPKICurrentPrefix, error) {
	var empty BGPRPKICurrentPrefix
	reference, err := VerifyBGPASPathHistorySourceInScope(ctx, sc, prefix, original, budget, authorize)
	if err != nil {
		return empty, err
	}
	source, err := decodeRetainedRoutingChangeSource(ctx, sc, original.Original, budget)
	if err != nil {
		return empty, err
	}
	if !sameRoutingChangeOriginal(source, reference) {
		return empty, change.ErrRouteReference
	}
	view := BGPRoutingViewRef{ID: source.ViewID, Generation: source.Generation}
	share := BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.WorkUnits / 2, StateBytes: budget.StateBytes}
	current, err := (BGPRouting{}).lookupExactPrefixInScope(ctx, sc, source.Source, view, prefix, share)
	if err != nil {
		return empty, err
	}
	fields, err := routingFlowPathFields(ctx, current.Paths, share)
	if err != nil {
		return empty, err
	}
	return BGPRPKICurrentPrefix{BGPRoutingLookup: current, PathFields: fields}, ctx.Err()
}
