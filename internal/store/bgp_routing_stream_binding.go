// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func resolveRoutingStreamSource(ctx context.Context, sc tenancy.Scope, base BGPRoutingSource, input BGPRoutingStreamInput, profile BGPRoutingBudget) (BGPRoutingSource, bool, error) {
	metadata, err := routingBaseAuthority(ctx, sc, base)
	if err != nil {
		return base, false, err
	}
	config, err := loadRoutingSourceConfiguration(ctx, sc, base.CollectorAgentID, base.SourceRef, profile)
	if err != nil {
		if routingMetadataRefusal(err) {
			return base, true, invalidateRoutingBaseViews(ctx, sc, base, input.Generation)
		}
		return base, false, err
	}
	if config.Manifest == nil && metadata.Epoch == "" {
		return base, false, nil
	}
	if config.Manifest == nil || config.Manifest.Epoch != metadata.Epoch || !config.Manifest.AssignedAt.Equal(metadata.AssignedAt) ||
		config.BaseContextID != base.ContextID || config.BaseRouterID != base.RouterID {
		return base, true, invalidateRoutingBaseViews(ctx, sc, base, input.Generation)
	}
	source, err := loadBoundRoutingStreamSource(ctx, sc, base, input.Generation, metadata.Epoch, profile)
	if err != nil {
		if routingMetadataRefusal(err) {
			return base, true, invalidateRoutingBaseViews(ctx, sc, base, input.Generation)
		}
		return base, false, err
	}
	if _, err := (BGPRouting{}).sourceAuthorityForWriteInScope(ctx, sc, source); err != nil {
		if routingMetadataRefusal(err) {
			return base, true, invalidateRoutingBaseViews(ctx, sc, base, input.Generation)
		}
		return base, false, err
	}
	return source, false, nil
}

// The opaque generation selects only already-owned rows; its retained target
// still needs exact current binding/credential authority. Every declared family
// must be present before any frame can renew a surviving family or be decoded.
func loadBoundRoutingStreamSource(ctx context.Context, sc tenancy.Scope, base BGPRoutingSource, generation, epoch string, profile BGPRoutingBudget) (BGPRoutingSource, error) {
	const selected = ` FROM bgp_routing_views WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3
 AND sender_serial=$4 AND origin_serial=$5 AND generation=$6 AND source_kind='router_bmp'
 AND view_kind='operator_loc_rib' AND routing_selection->>'epoch'=$7 AND state IN ('staging','current')`
	args := []any{base.TenantID, base.CollectorAgentID, base.SourceRef, base.SenderSerial, base.OriginSerial, generation, epoch}
	var count, encoded int64
	if err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(routing_selection::text)),0)::bigint`+selected, args...).Scan(&count, &encoded); err != nil {
		return base, err
	}
	if count < 1 || count > 2 {
		return base, ErrBGPRoutingSourceUnavailable
	}
	if encoded < 0 || encoded > profile.MemoryBytes/128 || encoded > profile.WorkUnits/16 {
		return base, ErrBGPRoutingBudget
	}
	// A third row is a duplicate or unsupported family, never permission to
	// choose two convenient members of a corrupted source incarnation.
	rows, err := sc.Q.Query(ctx, `SELECT context_id::text,router_id::text,observed_at,afi,safi,
 CASE WHEN octet_length(routing_selection::text)<=$8 THEN routing_selection ELSE NULL END`+selected+` ORDER BY afi,safi LIMIT 3 FOR UPDATE`, append(args, profile.MemoryBytes/128)...)
	if err != nil {
		return base, err
	}
	defer rows.Close()
	var source BGPRoutingSource
	var born time.Time
	var seen [3]bool
	for rows.Next() {
		candidate := base
		var raw []byte
		var afi uint16
		var safi uint8
		if err := rows.Scan(&candidate.ContextID, &candidate.RouterID, &candidate.ObservedAt, &afi, &safi, &raw); err != nil {
			return base, err
		}
		if afi < 1 || afi > 2 || safi != 1 || seen[afi] {
			return base, ErrBGPRoutingView
		}
		seen[afi] = true
		candidate.routingSelection, err = decodeRoutingSelection(ctx, raw, candidate, profile)
		if err != nil {
			return base, err
		}
		if candidate.routingSelection.BaseContextID != base.ContextID || candidate.routingSelection.BaseRouterID != base.RouterID ||
			candidate.routingSelection.Epoch != epoch || !routingSelectionSupportsAFI(candidate, afi) {
			return base, ErrBGPRoutingView
		}
		if source.routingSelection != nil && (!sameRoutingSelection(*source.routingSelection, *candidate.routingSelection) || !born.Equal(candidate.ObservedAt)) {
			return base, ErrBGPRoutingView
		}
		source, born = candidate, candidate.ObservedAt
	}
	if err := rows.Err(); err != nil {
		return base, err
	}
	if !routingStreamFamiliesComplete(source, seen) {
		return base, ErrBGPRoutingSourceUnavailable
	}
	source.ObservedAt = base.ObservedAt
	return source, nil
}

func routingStreamFamiliesComplete(source BGPRoutingSource, seen [3]bool) bool {
	if source.routingSelection == nil {
		return false
	}
	for _, afi := range source.routingSelection.Families {
		if !seen[afi] {
			return false
		}
	}
	return true
}
