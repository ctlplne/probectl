// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// StagePublicMRTSourceInScope binds original bytes to the current certified
// collector assignment. Malformed/admission-refused known sources commit
// retirement; storage/cancellation errors abort. No partial stage survives.
func (store BGPRouting) StagePublicMRTSourceInScope(ctx context.Context, sc tenancy.Scope, input BGPPublicSnapshotInput, profile BGPRoutingBudget, admitted bool) (BGPPublicSnapshotStageResult, error) {
	none := BGPPublicSnapshotStageResult{}
	if err := routingConfigurationScope(ctx, sc); err != nil {
		return none, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return none, err
	}
	var at time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
		return none, err
	}
	current := input
	current.ObservedAt = at
	source, err := resolvePublicSnapshotSource(ctx, sc, current)
	if err != nil {
		return none, err
	}
	if _, err := store.publicSourceAuthorityInScope(ctx, sc, source, true); err != nil {
		return none, err
	}
	refuse := func() (BGPPublicSnapshotStageResult, error) {
		if err := invalidatePublicSource(ctx, sc, source); err != nil {
			return none, err
		}
		return BGPPublicSnapshotStageResult{Status: "invalidated", ID: input.ObservationID}, nil
	}
	if !admitted {
		return refuse()
	}
	if input.Definitions != nil || input.SourceObservedUnixNanos != nil {
		return refuse()
	}
	table, err := bgp.DecodeMRTPeerIndex(ctx, input.SourceRecord, bgp.UpdateFrameBudget{MemoryBytes: profile.MemoryBytes, WorkUnits: profile.WorkUnits})
	if err != nil {
		if ctx.Err() != nil {
			return none, ctx.Err()
		}
		if publicMRTFrameRefusal(err) {
			return refuse()
		}
		return none, err
	}
	input.SourceObservedUnixNanos = &table.ObservedUnixNanos
	if _, err := sc.Q.Exec(ctx, "SAVEPOINT public_mrt_stage"); err != nil {
		return none, err
	}
	result, err := store.StagePublicSnapshotInScope(ctx, sc, input, profile)
	if err != nil {
		if ctx.Err() != nil {
			return none, ctx.Err()
		}
		if !publicMRTFrameRefusal(err) {
			return none, err
		}
		if _, err := sc.Q.Exec(ctx, "ROLLBACK TO SAVEPOINT public_mrt_stage"); err != nil {
			return none, err
		}
		return refuse()
	}
	if _, err := sc.Q.Exec(ctx, "RELEASE SAVEPOINT public_mrt_stage"); err != nil {
		return none, err
	}
	return result, nil
}
