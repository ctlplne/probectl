// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"strings"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/bgp"
)

// Raw TABLE_DUMP_V2 covers the supported unicast families in this complete
// source file. It grants no canonical router/context or selected-route claim.
func publicMRTSnapshotDefinitions(ctx context.Context, input BGPPublicSnapshotInput, profile BGPRoutingBudget) ([]BGPRoutingViewDefinition, error) {
	parts := strings.SplitN(input.SourceRef, "/", 3)
	if len(parts) != 3 {
		return nil, ErrBGPRoutingView
	}
	if (parts[0] != "ris" && parts[0] != "routeviews") || parts[1] != "mrt_table_dump_v2" || parts[2] == "" || strings.TrimSpace(parts[2]) != parts[2] || !utf8.ValidString(parts[2]) {
		return nil, ErrBGPRoutingView
	}
	table, err := bgp.DecodeMRTPeerIndex(ctx, input.SourceRecord, bgp.UpdateFrameBudget{MemoryBytes: profile.MemoryBytes, WorkUnits: profile.WorkUnits})
	if err != nil {
		return nil, err
	}
	if input.SourceObservedUnixNanos == nil || *input.SourceObservedUnixNanos != table.ObservedUnixNanos {
		return nil, ErrBGPRoutingView
	}
	if err := routingBatchPopulationCharge(&profile, len(table.Peers), 2048, 1024); err != nil {
		return nil, err
	}
	definitions := make([]BGPRoutingViewDefinition, 0, 2*len(table.Peers))
	for _, sourcePeer := range table.Peers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		bgpID, collectorID := sourcePeer.BGPIdentifier, table.CollectorIdentifier
		peer := &BGPPublicRoutingPeer{Feed: parts[0], Format: parts[1], Collector: parts[2], PeerAddress: sourcePeer.Address, PeerASN: sourcePeer.ASN, PeerBGPIdentifier: &bgpID, CollectorIdentifier: &collectorID, ViewName: table.ViewName}
		for _, afi := range []uint16{1, 2} {
			definitions = append(definitions, BGPRoutingViewDefinition{Kind: "public_bgp", AFI: afi, SAFI: 1, Public: peer})
		}
	}
	return definitions, nil
}

func samePublicSnapshotPeers(a, b []publicSnapshotPeer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].PeerKey != b[i].PeerKey || a[i].AFI != b[i].AFI || a[i].SAFI != b[i].SAFI || !bytes.Equal(a[i].Body, b[i].Body) {
			return false
		}
	}
	return true
}

func verifyPublicMRTSnapshotPeers(ctx context.Context, input BGPPublicSnapshotInput, peers []publicSnapshotPeer, definitions []BGPRoutingViewDefinition, profile BGPRoutingBudget) (BGPRoutingBudget, error) {
	expected := input
	expected.SourceRecord, expected.Definitions = nil, definitions
	original, _, remaining, err := preparePublicSnapshot(ctx, expected, profile)
	if err != nil {
		return profile, err
	}
	if !samePublicSnapshotPeers(peers, original) {
		return profile, ErrBGPRoutingView
	}
	return remaining, nil
}
