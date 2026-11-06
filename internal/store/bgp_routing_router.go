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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errBGPRoutingAmbiguousView = errors.New("router has conflicting complete selected views")

// This selector is only for an independently resolved canonical router in an
// authorized context. An exporter address, claimed peer ASN or row-supplied
// collector must never select that context. Multiple complete views are a
// conflict, not permission to pick whichever contains a convenient prefix.
func (store BGPRouting) lookupRouterInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope,
	routerID string, address netip.Addr, budget BGPRoutingBudget) (routingLookup, error) {
	if err := ctx.Err(); err != nil {
		return routingLookup{}, err
	}
	tenant, present := tenancy.FromContext(ctx)
	if !present || tenant != sc.Tenant || tenant.String() != scope.TenantID {
		return routingLookup{}, entity.ErrScopeMismatch
	}
	normalized, err := scope.Normalize()
	if err != nil || normalized != scope {
		return routingLookup{}, entity.ErrInvalidScope
	}
	if canonical, err := validRegistryUUID(routerID); err != nil || canonical != routerID {
		return routingLookup{}, entity.ErrInvalidScope
	}
	if !address.IsValid() || address.Zone() != "" {
		return routingLookup{}, ErrBGPRoutingView
	}
	if err := routingBatchCharge(&budget, 2048, 256); err != nil {
		return routingLookup{}, err
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return routingLookup{}, err
	}
	afi := uint16(2)
	if address.Is4() {
		afi = 1
	}
	// Do not hide a conflicting current manifest by prefix availability, source
	// credentials or grants. A stale/filtered single view is refused below; two
	// complete voices require an explicit source choice before route attribution.
	const selected = ` FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3
 AND source_kind='router_bmp' AND view_kind='loc_rib' AND afi=$4 AND safi=1
 AND state='current' AND completed_at IS NOT NULL`
	var count, encoded int64
	if err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(collector_agent_id)+octet_length(source_ref)+octet_length(sender_serial)+octet_length(origin_serial)),0)::bigint`+selected,
		scope.TenantID, scope.ContextID, routerID, afi).Scan(&count, &encoded); err != nil {
		return routingLookup{}, err
	}
	if count == 0 {
		return routingLookup{}, ErrBGPRoutingSourceUnavailable
	}
	if count != 1 {
		return routingLookup{}, errBGPRoutingAmbiguousView
	}
	if encoded < 0 || encoded > budget.MemoryBytes/8 || encoded > budget.WorkUnits/4 {
		return routingLookup{}, ErrBGPRoutingBudget
	}
	if err := routingBatchCharge(&budget, encoded*8, encoded*4); err != nil {
		return routingLookup{}, err
	}
	source := BGPRoutingSource{Scope: scope, RouterID: routerID}
	var ref BGPRoutingViewRef
	if err := sc.Q.QueryRow(ctx, `SELECT id::text,generation::text,collector_agent_id,source_ref,sender_serial,origin_serial,observed_at`+selected,
		scope.TenantID, scope.ContextID, routerID, afi).Scan(&ref.ID, &ref.Generation, &source.CollectorAgentID, &source.SourceRef, &source.SenderSerial, &source.OriginSerial, &source.ObservedAt); err != nil {
		return routingLookup{}, err
	}
	return store.lookupViewInScope(ctx, sc, source, ref, address, budget)
}

func requireRoutingReadSnapshot(ctx context.Context, sc tenancy.Scope) error {
	if sc.Q == nil {
		return ErrBGPRoutingSourceUnavailable
	}
	var isolation string
	if err := sc.Q.QueryRow(ctx, `SHOW transaction_isolation`).Scan(&isolation); err != nil {
		return err
	}
	if isolation != "repeatable read" && isolation != "serializable" {
		return errBGPRoutingReadSnapshot
	}
	return nil
}
