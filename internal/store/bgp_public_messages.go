// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

type BGPPublicSnapshotBatch struct {
	BGPRoutingViewRef
	BGPRoutingBatch
}

// BGPPublicSnapshotMessage describes one complete decoded source message. The
// receiver supplies authenticated collector identity and verifies whole-source
// completion; a RIS subscription or peer-up is never that completion proof.
// Original source time is immutable in the staged snapshot, not supplied here.
type BGPPublicSnapshotMessage struct {
	CollectorAgentID, SenderSerial, SourceRef, SnapshotID string
	Sequence                                              int64
	ObservedAt                                            time.Time
	WireDigest                                            []byte
	Complete, Reset                                       bool
	Batches                                               []BGPPublicSnapshotBatch
}

type preparedPublicBatch struct {
	BGPPublicSnapshotBatch
	changes []routingPreparedChange
	digest  [32]byte
}

func validatePublicSnapshotMessage(input BGPPublicSnapshotMessage) error {
	key := entity.SourceKey{AgentID: input.CollectorAgentID, Kind: entity.PublicBGP, SourceRef: input.SourceRef}
	if normalized, err := key.Normalize(); err != nil || normalized != key || input.SenderSerial == "" || strings.TrimSpace(input.SenderSerial) != input.SenderSerial {
		return entity.ErrInvalidClaim
	}
	if id, err := validRegistryUUID(input.SnapshotID); err != nil || id != input.SnapshotID {
		return ErrBGPRoutingView
	}
	if input.Sequence <= 0 || input.Sequence == math.MaxInt64 || len(input.WireDigest) != 32 || input.ObservedAt.IsZero() || input.ObservedAt.UnixNano() < 0 || !time.Unix(0, input.ObservedAt.UnixNano()).Equal(input.ObservedAt) || input.Complete && input.Reset || (input.Complete || input.Reset) && len(input.Batches) != 0 {
		return ErrBGPRoutingBatch
	}
	return nil
}

func preparePublicSnapshotMessage(ctx context.Context, input BGPPublicSnapshotMessage, profile BGPRoutingBudget) ([]preparedPublicBatch, [32]byte, error) {
	var digest [32]byte
	if err := ctx.Err(); err != nil {
		return nil, digest, err
	}
	if err := validatePublicSnapshotMessage(input); err != nil {
		return nil, digest, err
	}
	remaining := profile
	if err := routingBatchCharge(&remaining, 4096, 512); err != nil {
		return nil, digest, err
	}
	if err := routingBatchPopulationCharge(&remaining, len(input.Batches), 2048, 512); err != nil {
		return nil, digest, err
	}
	seen := make(map[BGPRoutingViewRef]bool, len(input.Batches))
	for _, batch := range input.Batches {
		for _, id := range []string{batch.ID, batch.Generation} {
			if normalized, err := validRegistryUUID(id); err != nil || normalized != id {
				return nil, digest, ErrBGPRoutingView
			}
		}
		if seen[batch.BGPRoutingViewRef] || batch.Sequence != input.Sequence || !batch.ObservedAt.Equal(input.ObservedAt) || batch.EndOfRIB || batch.Heartbeat {
			return nil, digest, ErrBGPRoutingBatch
		}
		seen[batch.BGPRoutingViewRef] = true
		var err error
		remaining, err = admitRoutingChanges(ctx, batch.Changes, batch.AFI, remaining)
		if err != nil {
			return nil, digest, err
		}
	}
	input.ObservedAt = input.ObservedAt.UTC()
	input.Batches = slices.Clone(input.Batches)
	prepared := make([]preparedPublicBatch, 0, len(input.Batches))
	for index, batch := range input.Batches {
		batch.ObservedAt = batch.ObservedAt.UTC()
		input.Batches[index] = batch
		changes, batchDigest, err := prepareRoutingBatch(ctx, batch.BGPRoutingBatch, batch.AFI, batch.SAFI, profile)
		if err != nil {
			return nil, digest, err
		}
		prepared = append(prepared, preparedPublicBatch{batch, changes, batchDigest})
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, digest, err
	}
	if int64(len(body)) > profile.MemoryBytes/4 {
		return nil, digest, ErrBGPRoutingBudget
	}
	if err := ctx.Err(); err != nil {
		return nil, digest, err
	}
	copy(digest[:], crypto.Hash(body))
	return prepared, digest, nil
}
