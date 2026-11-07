// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
)

// BGPPublicRoutingPeer retains a public collector observation, never a router
// identity or negotiated BMP session. Optional fields preserve absence, zero
// and complete source values. Neither these fields nor their digest grant
// tenant/source access or establish a complete/current RIB.
type BGPPublicRoutingPeer struct {
	Feed, Format, Collector    string
	PeerAddress                netip.Addr
	PeerASN                    uint32
	PeerBGPIdentifier          *uint32 `json:",omitempty"`
	CollectorIdentifier        *uint32 `json:",omitempty"`
	ViewName                   []byte
	ObservedUnixNanos          *int64 `json:",omitempty"`
	CollectorObservedUnixNanos *int64 `json:",omitempty"` // authenticated collector clock retained beyond database precision
	Cursor                     string `json:",omitempty"`
}

func publicRoutingViewMetadata(ctx context.Context, definition BGPRoutingViewDefinition, budget BGPRoutingBudget) ([]byte, [32]byte, error) {
	var empty [32]byte
	if err := ctx.Err(); err != nil {
		return nil, empty, err
	}
	if definition.Kind != "public_bgp" || definition.Public == nil || !emptyPublicBMPPeer(definition.Peer) ||
		(definition.AFI != 1 && definition.AFI != 2) || definition.SAFI != 1 {
		return nil, empty, ErrBGPRoutingView
	}
	peer := *definition.Public
	if (peer.Feed != "ris" && peer.Feed != "routeviews") ||
		(peer.Format != "mrt_table_dump_v2" && peer.Format != "ris_live") ||
		(peer.Feed == "routeviews" && peer.Format == "ris_live") ||
		peer.Collector == "" || strings.TrimSpace(peer.Collector) != peer.Collector ||
		!utf8.ValidString(peer.Collector) || !utf8.ValidString(peer.Cursor) || peer.PeerASN == 0 ||
		!peer.PeerAddress.IsValid() || peer.PeerAddress.Zone() != "" || peer.PeerAddress.IsUnspecified() || peer.PeerAddress.IsMulticast() ||
		(peer.ObservedUnixNanos != nil && *peer.ObservedUnixNanos < 0) ||
		(peer.CollectorObservedUnixNanos != nil && *peer.CollectorObservedUnixNanos < 0) {
		return nil, empty, ErrBGPRoutingView
	}
	if budget.MemoryBytes < 4096 || budget.WorkUnits < 4096 || budget.StateBytes <= 0 {
		return nil, empty, ErrBGPRoutingBudget
	}
	memory, work := budget.MemoryBytes-4096, budget.WorkUnits-4096
	for _, size := range []int64{int64(len(peer.Collector)), int64(len(peer.Cursor)), int64(len(peer.ViewName))} {
		if size > memory/16 || size > work/16 {
			return nil, empty, ErrBGPRoutingBudget
		}
		memory, work = memory-size*16, work-size*16
	}
	// Changing source clocks/cursors are retry metadata, not a new peer slot.
	identity := peer
	identity.ObservedUnixNanos, identity.Cursor = nil, ""
	identity.CollectorObservedUnixNanos = nil
	keyBody, err := json.Marshal(identity)
	if err != nil {
		return nil, empty, err
	}
	key := crypto.Hash(keyBody)
	if len(key) != len(empty) {
		return nil, empty, ErrBGPRoutingView
	}
	copy(empty[:], key)
	body, err := json.Marshal(peer)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if int64(len(body)) > budget.StateBytes || int64(len(body)) > memory/4 || int64(len(keyBody)) > work/4 {
		return nil, [32]byte{}, ErrBGPRoutingBudget
	}
	if err := ctx.Err(); err != nil {
		return nil, [32]byte{}, err
	}
	return body, empty, nil
}

func emptyPublicBMPPeer(peer BGPRoutingPeer) bool {
	return peer.SourceFormat == "" && peer.CollectorObservedUnixNanos == 0 && len(peer.OpenFrameDigest) == 0 &&
		peer.Type == 0 && peer.Flags == 0 && peer.Distinguisher == ([8]byte{}) && !peer.Address.IsValid() &&
		peer.ASN == 0 && !peer.BGPIdentifier.IsValid() && !peer.LocalAddress.IsValid() &&
		peer.LocalPort == 0 && peer.RemotePort == 0 && len(peer.SentOpen) == 0 && len(peer.ReceivedOpen) == 0 && len(peer.Information) == 0
}
