// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingBaseConfiguration struct {
	Epoch      string
	AssignedAt time.Time
}

// Credential control reads do not need to decode the potentially large routing
// manifest. A refused data admission must not prevent closing a known source.
func routingBaseAuthority(ctx context.Context, sc tenancy.Scope, base BGPRoutingSource) (routingBaseConfiguration, error) {
	var metadata routingBaseConfiguration
	if err := validateBGPRoutingSource(ctx, sc, base); err != nil {
		return metadata, err
	}
	if sc.Q == nil {
		return metadata, ErrBGPRoutingSourceUnavailable
	}
	var epoch *string
	var assigned *time.Time
	err := sc.Q.QueryRow(ctx, `SELECT routing_epoch::text,routing_assigned_at FROM entity_source_contexts
 WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='bmp_peer' AND source_ref=$3
 AND context_id=$4 AND anchor_entity_id=$5`, base.TenantID, base.CollectorAgentID, base.SourceRef, base.ContextID, base.RouterID).Scan(&epoch, &assigned)
	if errors.Is(err, pgx.ErrNoRows) {
		return metadata, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return metadata, err
	}
	if epoch != nil {
		if canonical, err := validRegistryUUID(*epoch); err != nil || canonical != *epoch || assigned == nil || assigned.After(base.ObservedAt) {
			return metadata, ErrBGPRoutingSourceUnavailable
		}
		metadata.Epoch, metadata.AssignedAt = *epoch, *assigned
	} else if assigned != nil {
		return metadata, ErrBGPRoutingView
	}
	if _, err := routingCredentialAuthority(ctx, sc, base, true, metadata.Epoch); err != nil {
		return metadata, err
	}
	return metadata, nil
}

func routingMetadataRefusal(err error) bool {
	return errors.Is(err, ErrBGPRoutingBudget) || errors.Is(err, ErrBGPRoutingView) || errors.Is(err, ErrBGPRoutingSourceUnavailable)
}

func invalidateRoutingBaseViews(ctx context.Context, sc tenancy.Scope, base BGPRoutingSource, generation string) error {
	var exact any
	if generation != "" {
		exact = generation
	}
	_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND source_kind='router_bmp'
 AND collector_context_id=$4 AND observed_at<=$5 AND state IN ('staging','current')
 AND ($6::uuid IS NULL OR generation=$6::uuid)`,
		base.TenantID, base.CollectorAgentID, base.SourceRef, base.ContextID, base.ObservedAt, exact)
	return err
}

// Only complete, current operator bindings can delegate a routing target. A
// missing decoded Peer Up is a base-source invalidation control, never a target
// grant. The original credentials must authorize either operation first.
func resolveRoutingStageSource(ctx context.Context, sc tenancy.Scope, base BGPRoutingSource, input BGPRoutingPeerUpInput, profile BGPRoutingBudget) (BGPRoutingSource, bool, error) {
	metadata, err := routingBaseAuthority(ctx, sc, base)
	if err != nil {
		return base, false, err
	}
	config, err := loadRoutingSourceConfiguration(ctx, sc, base.CollectorAgentID, base.SourceRef, profile)
	if err != nil {
		if routingMetadataRefusal(err) {
			return base, true, invalidateRoutingBaseViews(ctx, sc, base, "")
		}
		return base, false, err
	}
	if config.Manifest == nil {
		if metadata.Epoch != "" {
			return base, false, ErrBGPRoutingSourceUnavailable
		}
		return base, false, nil
	}
	if config.BaseContextID != base.ContextID || config.BaseRouterID != base.RouterID || config.Manifest.Epoch != metadata.Epoch || !config.Manifest.AssignedAt.Equal(metadata.AssignedAt) {
		return base, false, ErrBGPRoutingSourceUnavailable
	}
	if len(input.Definitions) == 0 || len(input.Definitions) > 2 {
		// An unprocessable source frame cannot keep older attribution alive.
		// A queued older frame must still preserve generations born after it.
		return base, true, invalidateRoutingBaseViews(ctx, sc, base, "")
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
