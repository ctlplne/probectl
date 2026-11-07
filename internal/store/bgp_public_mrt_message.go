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

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ApplyPublicMRTFrameInScope receives original source bytes, not interpreted
// paths or client-chosen view handles. Transport supplies the certified source
// identity. Complete means validated EOF of the configured whole source file;
// a route record or empty batch never manufactures that status.
func (store BGPRouting) ApplyPublicMRTFrameInScope(ctx context.Context, sc tenancy.Scope, input BGPPublicSnapshotMessage, frame []byte, profile BGPRoutingBudget, maxAge time.Duration) (BGPRoutingApplyResult, error) {
	if err := routingConfigurationScope(ctx, sc); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	if len(input.Batches) != 0 {
		return BGPRoutingApplyResult{}, ErrBGPRoutingBatch
	}
	// Resets are a bounded, identity-only invalidation path. Refused data need
	// no hashing, decoding or renewal, even when admission is exhausted.
	admitted := input.Reset || int64(len(frame)) <= profile.MemoryBytes/512 && int64(len(frame)) <= profile.WorkUnits/128
	input.WireDigest = make([]byte, 32)
	if admitted && !input.Reset {
		input.WireDigest = crypto.Hash(frame)
	}
	return store.applyPublicSnapshotMessage(ctx, sc, input, profile, maxAge, func(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, header publicSnapshotWriteState) ([]BGPPublicSnapshotBatch, error) {
		if !admitted || header.sourceRecord == nil {
			return nil, ErrBGPRoutingBudget
		}
		if input.Complete {
			if len(frame) != 0 {
				return nil, ErrBGPRoutingBatch
			}
			return nil, nil
		}
		return decodePublicMRTBatches(ctx, sc, source, header, input, frame, profile)
	})
}

func publicMRTFrameRefusal(err error) bool {
	return errors.Is(err, ErrBGPRoutingBatch) || errors.Is(err, ErrBGPRoutingView) || errors.Is(err, ErrBGPRoutingBudget) || errors.Is(err, ErrBGPRoutingSourceUnavailable) || errors.Is(err, bgp.ErrMRTRecord) || errors.Is(err, bgp.ErrMRTBudget)
}

func decodePublicMRTBatches(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, header publicSnapshotWriteState, input BGPPublicSnapshotMessage, frame []byte, profile BGPRoutingBudget) ([]BGPPublicSnapshotBatch, error) {
	table, err := bgp.DecodeMRTPeerIndex(ctx, header.sourceRecord, bgp.UpdateFrameBudget{MemoryBytes: profile.MemoryBytes / 2, WorkUnits: profile.WorkUnits / 2})
	if err != nil {
		return nil, err
	}
	decoded, err := bgp.DecodeMRTRIB(ctx, frame, len(table.Peers), bgp.UpdateFrameBudget{MemoryBytes: profile.MemoryBytes / 2, WorkUnits: profile.WorkUnits / 2})
	if err != nil {
		return nil, err
	}
	if decoded.ObservedUnixNanos > input.ObservedAt.UnixNano() {
		return nil, ErrBGPRoutingBatch
	}
	part := BGPPublicSnapshotInput{SourceRef: source.SourceRef, SourceRecord: header.sourceRecord, SourceObservedUnixNanos: header.sourceClock}
	definitions, err := publicMRTSnapshotDefinitions(ctx, part, profile)
	if err != nil {
		return nil, err
	}
	selected := make(map[uint16][32]byte)
	indices := make([]uint16, 0)
	keys := make([][]byte, 0)
	for _, entry := range decoded.Entries {
		if _, ok := selected[entry.PeerIndex]; ok {
			continue
		}
		definition := definitions[2*int(entry.PeerIndex)+int(decoded.Family.AFI)-1]
		_, key, err := publicRoutingViewMetadata(ctx, definition, profile)
		if err != nil {
			return nil, err
		}
		selected[entry.PeerIndex] = key
		indices = append(indices, entry.PeerIndex)
		keys = append(keys, key[:])
	}
	views, err := publicMRTViews(ctx, sc, source, input.SnapshotID, decoded.Family, keys, profile)
	if err != nil {
		return nil, err
	}
	batches := make([]BGPPublicSnapshotBatch, 0, len(indices))
	positions := make(map[uint16]int, len(indices))
	for _, index := range indices {
		positions[index] = len(batches)
		batches = append(batches, BGPPublicSnapshotBatch{BGPRoutingViewRef: views[selected[index]], BGPRoutingBatch: BGPRoutingBatch{Sequence: input.Sequence, AFI: decoded.Family.AFI, SAFI: decoded.Family.SAFI, ObservedAt: input.ObservedAt, WireDigest: input.WireDigest}})
	}
	for _, entry := range decoded.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		change := publicMRTRoutingChange(entry, decoded.ObservedUnixNanos, decoded.Sequence)
		index := positions[entry.PeerIndex]
		batches[index].Changes = append(batches[index].Changes, change)
	}
	return batches, nil
}

func publicMRTViews(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string, family bgp.RouteFamily, keys [][]byte, profile BGPRoutingBudget) (map[[32]byte]BGPRoutingViewRef, error) {
	if err := routingBatchPopulationCharge(&profile, len(keys), 2048, 1024); err != nil {
		return nil, err
	}
	views := make(map[[32]byte]BGPRoutingViewRef, len(keys))
	if len(keys) == 0 {
		return views, nil
	}
	rows, err := sc.Q.Query(ctx, `SELECT peer_key,id::text,generation::text FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND public_snapshot_id=$3 AND peer_key=ANY($4::bytea[]) AND afi=$5 AND safi=$6
 AND source_kind='public_bgp' AND collector_agent_id=$7 AND source_ref=$8 AND sender_serial=$9 AND state='staging'`, source.TenantID, source.ContextID, id, keys, family.AFI, family.SAFI, source.CollectorAgentID, source.SourceRef, source.SenderSerial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key []byte
		var ref BGPRoutingViewRef
		if err := rows.Scan(&key, &ref.ID, &ref.Generation); err != nil {
			return nil, err
		}
		if len(key) != 32 || len(views) >= len(keys) {
			return nil, ErrBGPRoutingView
		}
		var fixed [32]byte
		copy(fixed[:], key)
		if _, duplicate := views[fixed]; duplicate {
			return nil, ErrBGPRoutingView
		}
		views[fixed] = ref
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(views) != len(keys) {
		return nil, ErrBGPRoutingSourceUnavailable
	}
	return views, nil
}

func publicMRTRoutingChange(entry bgp.MRTRIBEntry, recordClock int64, recordSequence uint32) BGPRoutingChange {
	change := BGPRoutingChange{Prefix: entry.Route.Prefix, HasPathID: entry.Route.HasPathID, PathID: entry.Route.PathID, NextHops: entry.NextHops}
	change.Segments = make([]BGPRoutingSegment, len(entry.Path.Path.Segments))
	for i, segment := range entry.Path.Path.Segments {
		change.Segments[i] = BGPRoutingSegment{Kind: uint8(segment.Kind), Values: segment.Values}
	}
	change.Attributes.Wire = make([]BGPRoutingAttribute, len(entry.Attributes))
	for i, attribute := range entry.Attributes {
		change.Attributes.Wire[i] = BGPRoutingAttribute{Flags: attribute.Flags, Type: attribute.Type, Value: attribute.Value}
	}
	change.Attributes.MRT = &BGPRoutingMRTRecord{RecordUnixNanos: recordClock, OriginatedUnixNanos: entry.OriginatedUnixNanos, Sequence: recordSequence, PeerIndex: entry.PeerIndex}
	return change
}
