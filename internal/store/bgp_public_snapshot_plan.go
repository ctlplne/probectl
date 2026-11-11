// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

// BGPPublicSnapshotInput has no tenant, context or router selector. Transport
// supplies the current collector identity; the operator source assignment
// resolves its context. Definitions must be one complete decoded peer manifest.
// Present empty means an empty manifest. Nil means unavailable unless a full
// original SourceRecord supplies its own verified peer table.
type BGPPublicSnapshotInput struct {
	CollectorAgentID, SenderSerial, SourceRef, ObservationID string
	SourceObservedUnixNanos                                  *int64 // original RIB production clock, never the collector receipt
	ObservedAt                                               time.Time
	Definitions                                              []BGPRoutingViewDefinition
	SourceRecord                                             []byte // complete raw MRT peer table; nil for normalized internal inputs
}

type publicSnapshotPeer struct {
	PeerKey [32]byte
	AFI     uint16
	SAFI    uint8
	Body    json.RawMessage
}

func preparePublicSnapshot(ctx context.Context, input BGPPublicSnapshotInput, profile BGPRoutingBudget) ([]publicSnapshotPeer, [32]byte, BGPRoutingBudget, error) {
	var digest [32]byte
	if err := ctx.Err(); err != nil {
		return nil, digest, profile, err
	}
	var sourceRecordDigest []byte
	var sourceDefinitions []BGPRoutingViewDefinition
	if input.SourceRecord != nil {
		if err := routingBatchPopulationCharge(&profile, len(input.SourceRecord), 128, 32); err != nil {
			return nil, digest, profile, err
		}
		var err error
		sourceDefinitions, err = publicMRTSnapshotDefinitions(ctx, input, profile)
		if err != nil {
			return nil, digest, profile, err
		}
		if input.Definitions == nil {
			input.Definitions = sourceDefinitions
		}
		sourceRecordDigest = crypto.Hash(input.SourceRecord)
	}
	key := entity.SourceKey{AgentID: input.CollectorAgentID, Kind: entity.PublicBGP, SourceRef: input.SourceRef}
	if normalized, err := key.Normalize(); err != nil || normalized != key || input.SenderSerial == "" || strings.TrimSpace(input.SenderSerial) != input.SenderSerial {
		return nil, digest, profile, entity.ErrInvalidClaim
	}
	if id, err := validRegistryUUID(input.ObservationID); err != nil || id != input.ObservationID || input.Definitions == nil || input.ObservedAt.IsZero() ||
		!time.Unix(0, input.ObservedAt.UnixNano()).Equal(input.ObservedAt) || input.ObservedAt.UnixNano() < 0 {
		return nil, digest, profile, ErrBGPRoutingView
	}
	if input.SourceObservedUnixNanos != nil && *input.SourceObservedUnixNanos < 0 {
		return nil, digest, profile, ErrBGPRoutingView
	}
	if err := routingBatchPopulationCharge(&profile, len(input.Definitions), 1024, 512); err != nil {
		return nil, digest, profile, err
	}
	peers := make([]publicSnapshotPeer, 0, len(input.Definitions))
	seen := make(map[struct {
		key [32]byte
		afi uint16
	}]bool, len(input.Definitions))
	for _, definition := range input.Definitions {
		if definition.Public == nil || publicRoutingSourceRef(*definition.Public) != input.SourceRef || definition.Filtered {
			return nil, digest, profile, ErrBGPRoutingView
		}
		peer := *definition.Public
		clock := input.ObservedAt.UnixNano()
		peer.CollectorObservedUnixNanos = &clock
		definition.Public = &peer
		body, key, err := publicRoutingViewMetadata(ctx, definition, profile)
		if err != nil {
			return nil, digest, profile, err
		}
		if err := routingBatchPopulationCharge(&profile, len(body), 32, 32); err != nil {
			return nil, digest, profile, err
		}
		slot := struct {
			key [32]byte
			afi uint16
		}{key, definition.AFI}
		if seen[slot] {
			return nil, digest, profile, ErrBGPRoutingView
		}
		seen[slot] = true
		peers = append(peers, publicSnapshotPeer{key, definition.AFI, definition.SAFI, body})
	}
	slices.SortFunc(peers, func(a, b publicSnapshotPeer) int {
		if cmp := bytes.Compare(a.PeerKey[:], b.PeerKey[:]); cmp != 0 {
			return cmp
		}
		return int(a.AFI) - int(b.AFI)
	})
	if sourceDefinitions != nil {
		var err error
		profile, err = verifyPublicMRTSnapshotPeers(ctx, input, peers, sourceDefinitions, profile)
		if err != nil {
			return nil, digest, profile, err
		}
	}
	manifest, err := json.Marshal(struct {
		Version                 int
		SourceObservedUnixNanos *int64 `json:",omitempty"`
		SourceRecordDigest      []byte `json:",omitempty"`
		Peers                   []publicSnapshotPeer
	}{1, input.SourceObservedUnixNanos, sourceRecordDigest, peers})
	if err != nil {
		return nil, digest, profile, err
	}
	if err := routingBatchPopulationCharge(&profile, len(manifest), 8, 8); err != nil {
		return nil, digest, profile, err
	}
	if err := ctx.Err(); err != nil {
		return nil, digest, profile, err
	}
	copy(digest[:], crypto.Hash(manifest))
	return peers, digest, profile, nil
}
