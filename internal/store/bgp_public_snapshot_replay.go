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

func replayPublicSnapshot(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string, peers []publicSnapshotPeer, digest [32]byte, asOf time.Time) (BGPPublicSnapshotStageResult, bool, error) {
	none := BGPPublicSnapshotStageResult{}
	var owned, identical bool
	var state string
	var until time.Time
	err := sc.Q.QueryRow(ctx, `SELECT collector_agent_id=$4 AND source_ref=$5,
 sender_serial=$6 AND manifest_digest=$7 AND observed_unix_nanos=$8 AND expected_views=$9,state,valid_until
 FROM bgp_public_snapshots WHERE tenant_id=$1 AND context_id=$2 AND id=$3 FOR UPDATE`, source.TenantID, source.ContextID, id, source.CollectorAgentID, source.SourceRef, source.SenderSerial, digest[:], source.ObservedAt.UnixNano(), int64(len(peers))).Scan(&owned, &identical, &state, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, false, nil
	}
	if err != nil {
		return none, false, err
	}
	if !owned {
		return none, true, ErrBGPRoutingSourceUnavailable
	}
	if !identical || state == "invalid" || !until.After(asOf) {
		result, err := invalidatePublicSnapshot(ctx, sc, source, id)
		return result, true, err
	}
	var count int64
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND public_snapshot_id=$3`, source.TenantID, source.ContextID, id).Scan(&count); err != nil {
		return none, true, err
	}
	if count != int64(len(peers)) {
		result, err := invalidatePublicSnapshot(ctx, sc, source, id)
		return result, true, err
	}
	views := make([]BGPPublicSnapshotView, 0, len(peers))
	for _, peer := range peers {
		view := BGPPublicSnapshotView{PeerKey: peer.PeerKey, AFI: peer.AFI, SAFI: peer.SAFI}
		err := sc.Q.QueryRow(ctx, `SELECT id::text,generation::text FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND public_snapshot_id=$3 AND peer_key=$4 AND afi=$5 AND safi=$6
 AND source_kind='public_bgp' AND collector_agent_id=$7 AND source_ref=$8 AND sender_serial=$9
 AND peer_identity=$10::jsonb AND state IN ('staging','current')`, source.TenantID, source.ContextID, id, peer.PeerKey[:], peer.AFI, peer.SAFI, source.CollectorAgentID, source.SourceRef, source.SenderSerial, string(peer.Body)).Scan(&view.ID, &view.Generation)
		if errors.Is(err, pgx.ErrNoRows) {
			result, err := invalidatePublicSnapshot(ctx, sc, source, id)
			return result, true, err
		}
		if err != nil {
			return none, true, err
		}
		views = append(views, view)
	}
	current, err := (BGPRouting{}).publicSourceAuthorityInScope(ctx, sc, source, true)
	if err != nil {
		return none, true, err
	}
	if !until.After(current.AsOf) {
		result, err := invalidatePublicSnapshot(ctx, sc, source, id)
		return result, true, err
	}
	// A replay returns the same incarnation and lease. It creates no rows,
	// extends no expiry and cannot turn an invalidated header current again.
	return BGPPublicSnapshotStageResult{Status: "replayed", ID: id, Views: views}, true, nil
}

func invalidatePublicSnapshot(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string) (BGPPublicSnapshotStageResult, error) {
	if _, err := sc.Q.Exec(ctx, `UPDATE bgp_public_snapshots SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND collector_agent_id=$4 AND source_ref=$5`, source.TenantID, source.ContextID, id, source.CollectorAgentID, source.SourceRef); err != nil {
		return BGPPublicSnapshotStageResult{}, err
	}
	if _, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND public_snapshot_id=$3 AND collector_agent_id=$4 AND source_ref=$5 AND source_kind='public_bgp'`, source.TenantID, source.ContextID, id, source.CollectorAgentID, source.SourceRef); err != nil {
		return BGPPublicSnapshotStageResult{}, err
	}
	return BGPPublicSnapshotStageResult{Status: "invalidated", ID: id}, nil
}
