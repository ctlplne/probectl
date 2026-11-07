// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPRoutingStreamInput carries authenticated source identity and an opaque
// generation returned by staging. No packet chooses a tenant, router or context.
// Sequence/ObservedAt belong to one complete source message across all families.
type BGPRoutingStreamInput struct {
	CollectorAgentID, SenderSerial, SourceRef, OriginSerial, Generation string
	ObservedAt                                                          time.Time
	Sequence                                                            int64
	Reset                                                               bool
}

// ApplyPeerMessageInScope holds current source authority while the receiver
// decodes a complete frame against retained OPEN metadata. The decoder is trusted
// service code, not a user callback. Every staged family advances atomically;
// any malformed, gapped or partially persisted message invalidates this exact
// generation before refusal is acknowledged. The caller must commit refusals.
func (store BGPRouting) ApplyPeerMessageInScope(ctx context.Context, sc tenancy.Scope, input BGPRoutingStreamInput, profile BGPRoutingBudget,
	decode func(context.Context, BGPRoutingPeer, []BGPRoutingStagedView) ([]BGPRoutingBatch, error)) (BGPRoutingApplyResult, error) {
	source, handled, err := store.authorizeRoutingStream(ctx, sc, input, profile)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	if handled {
		return BGPRoutingApplyResult{Status: "invalidated"}, nil
	}
	if input.Reset {
		return invalidateRoutingStream(ctx, sc, source, input.Generation, "source-reset")
	}
	if _, err := sc.Q.Exec(ctx, "SAVEPOINT routing_stream_message"); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	peer, refs, err := loadRoutingStreamMetadata(ctx, sc, source, input.Generation, profile)
	if err != nil || decode == nil {
		return rollbackRoutingStream(ctx, sc, source, input.Generation)
	}
	batches, err := decode(ctx, peer, append([]BGPRoutingStagedView(nil), refs...))
	if ctx.Err() != nil {
		return BGPRoutingApplyResult{}, ctx.Err()
	}
	if err != nil || !routingStreamPlanMatches(refs, batches) {
		return rollbackRoutingStream(ctx, sc, source, input.Generation)
	}
	return store.persistRoutingStream(ctx, sc, source, input, refs, batches, profile)
}

func (store BGPRouting) authorizeRoutingStream(ctx context.Context, sc tenancy.Scope, input BGPRoutingStreamInput, profile BGPRoutingBudget) (BGPRoutingSource, bool, error) {
	up := BGPRoutingPeerUpInput{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, OriginSerial: input.OriginSerial, ObservationID: input.Generation, ObservedAt: input.ObservedAt}
	source, err := routingStageSource(ctx, sc, up, profile)
	if err != nil {
		return source, false, err
	}
	if id, err := validRegistryUUID(input.Generation); err != nil || id != input.Generation {
		return source, false, ErrBGPRoutingView
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return source, false, err
	}
	source, handled, err := resolveRoutingStreamSource(ctx, sc, source, input, profile)
	if err != nil || handled {
		return source, handled, err
	}
	if _, err := store.sourceAuthorityForWriteInScope(ctx, sc, source); err != nil {
		return source, false, err
	}
	return source, false, nil
}

func loadRoutingStreamMetadata(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, generation string, profile BGPRoutingBudget) (BGPRoutingPeer, []BGPRoutingStagedView, error) {
	selection, err := routingSelectionJSON(source)
	if err != nil {
		return BGPRoutingPeer{}, nil, err
	}
	kind := "loc_rib"
	if source.routingSelection != nil {
		kind = "operator_loc_rib"
	}
	rows, err := sc.Q.Query(ctx, `SELECT id::text,afi,safi,CASE WHEN octet_length(peer_identity::text)<=$9 THEN peer_identity ELSE NULL END FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4 AND source_ref=$5
 AND sender_serial=$6 AND origin_serial=$7 AND generation=$8 AND source_kind='router_bmp'
 AND view_kind=$10 AND routing_selection IS NOT DISTINCT FROM $11::jsonb ORDER BY afi,safi FOR UPDATE`, source.TenantID, source.ContextID, source.RouterID,
		source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial, generation, profile.MemoryBytes/32, kind, selection)
	if err != nil {
		return BGPRoutingPeer{}, nil, err
	}
	defer rows.Close()
	var peer BGPRoutingPeer
	var canonical []byte
	var refs []BGPRoutingStagedView
	var seen [3]bool
	for rows.Next() {
		var ref BGPRoutingStagedView
		var raw []byte
		if err := rows.Scan(&ref.ID, &ref.AFI, &ref.SAFI, &raw); err != nil {
			return BGPRoutingPeer{}, nil, err
		}
		if ref.AFI < 1 || ref.AFI > 2 || ref.SAFI != 1 || seen[ref.AFI] || routingBatchPopulationCharge(&profile, len(raw), 16, 8) != nil {
			return BGPRoutingPeer{}, nil, ErrBGPRoutingView
		}
		seen[ref.AFI] = true
		var current BGPRoutingPeer
		if json.Unmarshal(raw, &current) != nil || current.Type != 3 || len(current.OpenFrameDigest) != 32 {
			return BGPRoutingPeer{}, nil, ErrBGPRoutingView
		}
		if !routingStreamPeerMatchesSource(source, current, ref.AFI, ref.SAFI) {
			return BGPRoutingPeer{}, nil, ErrBGPRoutingView
		}
		body, err := json.Marshal(current)
		if err != nil || canonical != nil && string(canonical) != string(body) {
			return BGPRoutingPeer{}, nil, ErrBGPRoutingView
		}
		peer, canonical, ref.Generation = current, body, generation
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return BGPRoutingPeer{}, nil, err
	}
	if len(refs) == 0 {
		return BGPRoutingPeer{}, nil, ErrBGPRoutingSourceUnavailable
	}
	return peer, refs, nil
}

func routingStreamPeerMatchesSource(source BGPRoutingSource, peer BGPRoutingPeer, afi uint16, safi uint8) bool {
	if source.routingSelection == nil {
		return peer.Distinguisher == ([8]byte{}) && peer.SourceFormat == ""
	}
	_, err := routingStoredViewKind(source, BGPRoutingViewDefinition{Kind: "loc_rib", AFI: afi, SAFI: safi, Peer: peer})
	return err == nil
}

func routingStreamPlanMatches(refs []BGPRoutingStagedView, batches []BGPRoutingBatch) bool {
	if len(refs) != len(batches) {
		return false
	}
	for i, ref := range refs {
		if batches[i].AFI != ref.AFI || batches[i].SAFI != ref.SAFI {
			return false
		}
	}
	return true
}

func (store BGPRouting) persistRoutingStream(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, input BGPRoutingStreamInput, refs []BGPRoutingStagedView, batches []BGPRoutingBatch, profile BGPRoutingBudget) (BGPRoutingApplyResult, error) {
	profile.MemoryBytes /= int64(len(refs))
	profile.WorkUnits /= int64(len(refs))
	status := ""
	for i, ref := range refs {
		batch := batches[i]
		batch.Sequence, batch.ObservedAt = input.Sequence, input.ObservedAt
		result, err := store.applyBatchInScope(ctx, sc, source, ref.BGPRoutingViewRef, batch, profile)
		if err != nil || result.Status == "invalidated" || status != "" && status != result.Status {
			return rollbackRoutingStream(ctx, sc, source, input.Generation)
		}
		status = result.Status
	}
	for _, ref := range refs {
		view, err := loadRoutingWriteView(ctx, sc, source, ref.BGPRoutingViewRef)
		if err != nil {
			return rollbackRoutingStream(ctx, sc, source, input.Generation)
		}
		birth := source
		birth.ObservedAt = view.born
		if err := store.checkRoutingWriteLease(ctx, sc, birth, view.validUntil); err != nil {
			return rollbackRoutingStream(ctx, sc, source, input.Generation)
		}
	}
	if _, err := sc.Q.Exec(ctx, "RELEASE SAVEPOINT routing_stream_message"); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	return BGPRoutingApplyResult{Status: status}, nil
}

func rollbackRoutingStream(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, generation string) (BGPRoutingApplyResult, error) {
	if _, err := sc.Q.Exec(ctx, "ROLLBACK TO SAVEPOINT routing_stream_message"); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	return invalidateRoutingStream(ctx, sc, source, generation, "whole-message-refusal")
}

func invalidateRoutingStream(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, generation, reason string) (BGPRoutingApplyResult, error) {
	_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4 AND source_ref=$5
 AND sender_serial=$6 AND origin_serial=$7 AND generation=$8 AND source_kind='router_bmp'`,
		source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial, generation)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	return BGPRoutingApplyResult{Status: "invalidated", Reason: reason}, nil
}
