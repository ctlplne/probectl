// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type BGPPublicSnapshotView struct {
	BGPRoutingViewRef
	PeerKey [32]byte
	AFI     uint16
	SAFI    uint8
}

type BGPPublicSnapshotStageResult struct {
	Status string // staged, replayed or invalidated; never a publication grant
	ID     string
	Views  []BGPPublicSnapshotView
}

// StagePublicSnapshotInScope requires one fenced read-committed transaction.
// Return every error from its callback so no partial replacement commits.
// Successful staging withdraws the former source cohort but publishes nothing.
func (store BGPRouting) StagePublicSnapshotInScope(ctx context.Context, sc tenancy.Scope, input BGPPublicSnapshotInput, profile BGPRoutingBudget) (BGPPublicSnapshotStageResult, error) {
	none := BGPPublicSnapshotStageResult{}
	if err := routingConfigurationScope(ctx, sc); err != nil {
		return none, err
	}
	if input.SourceObservedUnixNanos != nil {
		clock := *input.SourceObservedUnixNanos
		input.SourceObservedUnixNanos = &clock
	}
	peers, digest, operation, err := preparePublicSnapshot(ctx, input, profile)
	if err != nil {
		return none, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return none, err
	}
	source, err := resolvePublicSnapshotSource(ctx, sc, input)
	if err != nil {
		return none, err
	}
	authority, err := store.publicSourceAuthorityInScope(ctx, sc, source, true)
	if err != nil {
		return none, err
	}
	if replay, exists, err := replayPublicSnapshot(ctx, sc, source, input.ObservationID, peers, digest, input.SourceObservedUnixNanos, input.SourceRecord, authority.AsOf); err != nil || exists {
		return replay, err
	}
	var latest *int64
	if err := sc.Q.QueryRow(ctx, `SELECT max(observed_unix_nanos) FROM bgp_public_snapshots
 WHERE tenant_id=$1 AND context_id=$2 AND collector_agent_id=$3 AND source_ref=$4`, source.TenantID, source.ContextID, source.CollectorAgentID, source.SourceRef).Scan(&latest); err != nil {
		return none, err
	}
	if latest != nil && input.ObservedAt.UnixNano() <= *latest {
		return none, ErrBGPRoutingSourceUnavailable
	}
	until := input.ObservedAt.Add(profile.LeaseDuration)
	if authority.ValidUntil.Before(until) {
		until = authority.ValidUntil
	}
	if !until.After(authority.AsOf) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	charge := int64(512)
	if int64(len(input.SourceRecord)) > profile.StateBytes-charge {
		return none, ErrBGPRoutingBudget
	}
	charge += int64(len(input.SourceRecord))
	for _, value := range []string{source.CollectorAgentID, source.SourceRef, source.SenderSerial} {
		if int64(len(value)) > profile.StateBytes-charge {
			return none, ErrBGPRoutingBudget
		}
		charge += int64(len(value))
	}
	used, err := routingStateBytesInScope(ctx, sc)
	if err != nil {
		return none, err
	}
	if used < 0 || charge > profile.StateBytes || used > profile.StateBytes-charge {
		return none, ErrBGPRoutingBudget
	}
	if err := invalidatePublicSource(ctx, sc, source); err != nil {
		return none, err
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_public_snapshots
 (tenant_id,context_id,id,collector_agent_id,source_ref,sender_serial,manifest_digest,expected_views,state,
 observed_at,observed_unix_nanos,last_message_unix_nanos,valid_until,charged_bytes,source_observed_unix_nanos,source_record)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'staging',$9,$10,$10,$11,$12,$13,$14)`, source.TenantID, source.ContextID, input.ObservationID, source.CollectorAgentID, source.SourceRef, source.SenderSerial,
		digest[:], int64(len(peers)), source.ObservedAt, source.ObservedAt.UnixNano(), until, charge, input.SourceObservedUnixNanos, input.SourceRecord); err != nil {
		return none, err
	}
	views := make([]BGPPublicSnapshotView, 0, len(peers))
	for _, peer := range peers {
		if err := routingBatchPopulationCharge(&operation, len(peer.Body), 16, 16); err != nil {
			return none, err
		}
		var metadata BGPPublicRoutingPeer
		if err := json.Unmarshal(peer.Body, &metadata); err != nil {
			return none, err
		}
		definition := BGPRoutingViewDefinition{Kind: "public_bgp", AFI: peer.AFI, SAFI: peer.SAFI, Public: &metadata}
		view, err := store.beginPublicViewInScope(ctx, sc, source, definition, operation)
		if err != nil {
			return none, err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET public_snapshot_id=$5 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, view.ID, view.Generation, input.ObservationID); err != nil {
			return none, err
		}
		views = append(views, BGPPublicSnapshotView{BGPRoutingViewRef: BGPRoutingViewRef{ID: view.ID, Generation: view.Generation}, PeerKey: peer.PeerKey, AFI: peer.AFI, SAFI: peer.SAFI})
	}
	current, err := store.publicSourceAuthorityInScope(ctx, sc, source, true)
	if err != nil {
		return none, err
	}
	if !until.After(current.AsOf) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	return BGPPublicSnapshotStageResult{Status: "staged", ID: input.ObservationID, Views: views}, nil
}

func resolvePublicSnapshotSource(ctx context.Context, sc tenancy.Scope, input BGPPublicSnapshotInput) (BGPPublicRoutingSource, error) {
	source := BGPPublicRoutingSource{Scope: entity.Scope{TenantID: sc.Tenant.String()}, CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, ObservedAt: input.ObservedAt}
	err := sc.Q.QueryRow(ctx, `SELECT context_id::text FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='public_bgp' AND source_ref=$3`, source.TenantID, source.CollectorAgentID, source.SourceRef).Scan(&source.ContextID)
	if errors.Is(err, pgx.ErrNoRows) {
		return BGPPublicRoutingSource{}, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return BGPPublicRoutingSource{}, err
	}
	return source, validatePublicRoutingSource(ctx, sc, source)
}

func invalidatePublicSource(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource) error {
	if _, err := sc.Q.Exec(ctx, `UPDATE bgp_public_snapshots SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND collector_agent_id=$3 AND source_ref=$4 AND state IN ('staging','current')`, source.TenantID, source.ContextID, source.CollectorAgentID, source.SourceRef); err != nil {
		return err
	}
	_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND collector_agent_id=$3 AND source_ref=$4 AND source_kind='public_bgp' AND state IN ('staging','current')`, source.TenantID, source.ContextID, source.CollectorAgentID, source.SourceRef)
	return err
}
