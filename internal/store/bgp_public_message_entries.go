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

func persistPublicSnapshotBatch(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, snapshot string, batch preparedPublicBatch, profile BGPRoutingBudget) error {
	var view routingWriteView
	err := sc.Q.QueryRow(ctx, `SELECT state,afi,safi,charged_bytes,row_count,valid_until FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND public_snapshot_id=$3 AND id=$4 AND generation=$5
 AND source_kind='public_bgp' AND collector_agent_id=$6 AND source_ref=$7 AND sender_serial=$8 FOR UPDATE`, source.TenantID, source.ContextID, snapshot, batch.ID, batch.Generation, source.CollectorAgentID, source.SourceRef, source.SenderSerial).Scan(&view.state, &view.afi, &view.safi, &view.bytes, &view.rows, &view.validUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return err
	}
	if view.state != "staging" || view.afi != batch.AFI || view.safi != batch.SAFI || !view.validUntil.After(source.ObservedAt) {
		return ErrBGPRoutingView
	}
	plan, used, rows, err := planRoutingChanges(ctx, sc, source.Scope, batch.BGPRoutingViewRef, view, batch.changes, profile)
	if err != nil {
		return err
	}
	if err := persistRoutingChanges(ctx, sc, source.Scope, batch.BGPRoutingViewRef, batch.BGPRoutingBatch, plan); err != nil {
		return err
	}
	_, err = sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET charged_bytes=$5,row_count=$6,last_sequence=$7,next_sequence=$7::bigint+1,
 last_digest=$8,last_message_observed_at=$9,message_clock_sequence=$7,updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, batch.ID, batch.Generation, used, rows, batch.Sequence, batch.digest[:], batch.ObservedAt)
	return err
}

func finishPublicSnapshotMessage(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, input BGPPublicSnapshotMessage, header publicSnapshotWriteState, digest [32]byte, until time.Time) error {
	if input.Complete {
		updated, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='current',completed_at=clock_timestamp(),
 valid_until=LEAST(valid_until,$4),updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND public_snapshot_id=$3 AND state='staging'`, source.TenantID, source.ContextID, input.SnapshotID, until)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != header.expectedViews {
			return ErrBGPRoutingView
		}
	}
	updated, err := sc.Q.Exec(ctx, `UPDATE bgp_public_snapshots SET last_sequence=$4,next_sequence=$4::bigint+1,last_digest=$5,
 last_message_unix_nanos=$6,valid_until=$7,state=CASE WHEN $8 THEN 'current' ELSE state END,
 completed_at=CASE WHEN $8 THEN clock_timestamp() ELSE completed_at END,updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND state='staging'`, source.TenantID, source.ContextID, input.SnapshotID, input.Sequence, digest[:], input.ObservedAt.UnixNano(), until, input.Complete)
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return ErrBGPRoutingView
	}
	return nil
}
