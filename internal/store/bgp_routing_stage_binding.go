// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Only complete, current operator bindings can delegate a routing target. A
// missing decoded Peer Up is a base-source invalidation control, never a target
// grant. The original credentials must authorize either operation first.
func resolveRoutingStageSource(ctx context.Context, sc tenancy.Scope, base BGPRoutingSource, input BGPRoutingPeerUpInput, profile BGPRoutingBudget) (BGPRoutingSource, bool, error) {
	config, err := loadRoutingSourceConfiguration(ctx, sc, base.CollectorAgentID, base.SourceRef, profile)
	if err != nil {
		return base, false, err
	}
	if config.Manifest == nil {
		return base, false, nil
	}
	if config.BaseContextID != base.ContextID || config.BaseRouterID != base.RouterID || config.Manifest.AssignedAt.After(base.ObservedAt) {
		return base, false, ErrBGPRoutingSourceUnavailable
	}
	if _, err := routingCredentialAuthority(ctx, sc, base, true, config.Manifest.Epoch); err != nil {
		return base, false, err
	}
	if len(input.Definitions) == 0 || len(input.Definitions) > 2 {
		// An unprocessable source frame cannot keep older attribution alive.
		// A queued older frame must still preserve generations born after it.
		_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND source_kind='router_bmp'
 AND collector_context_id=$4 AND observed_at<=$5 AND state IN ('staging','current')`,
			base.TenantID, base.CollectorAgentID, base.SourceRef, base.ContextID, base.ObservedAt)
		return base, true, err
	}
	families := make([]uint16, 0, len(input.Definitions))
	for _, definition := range input.Definitions {
		families = append(families, definition.AFI)
	}
	selected, err := selectRoutingSource(ctx, sc, config, input.Definitions[0].Peer, families)
	if err != nil {
		return base, false, err
	}
	base.ContextID, base.RouterID, base.routingSelection = selected.ContextID, selected.RouterID, &selected
	return base, false, nil
}

func routingSourceSlot(source BGPRoutingSource) (any, string) {
	if source.routingSelection == nil {
		return nil, ""
	}
	return source.routingSelection.Epoch, source.routingSelection.BindingID
}

func routingStageNonceConflicts(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, generation string) (bool, error) {
	selection, err := routingSelectionJSON(source)
	if err != nil {
		return false, err
	}
	var conflict bool
	err = sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bgp_routing_views
 WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND generation=$4 AND source_kind='router_bmp'
 AND NOT (context_id=$5 AND router_id=$6 AND sender_serial=$7 AND origin_serial=$8
          AND routing_selection IS NOT DISTINCT FROM $9::jsonb))`,
		source.TenantID, source.CollectorAgentID, source.SourceRef, generation, source.ContextID, source.RouterID,
		source.SenderSerial, source.OriginSerial, selection).Scan(&conflict)
	return conflict, err
}
