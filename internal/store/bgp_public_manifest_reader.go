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
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Verify the complete retained peer manifest, not only the peer carrying the
// last route. Every row must still belong to this exact source incarnation.
func verifyPublicSnapshotManifest(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string, header publicSnapshotWriteState, profile BGPRoutingBudget) error {
	rows, err := sc.Q.Query(ctx, `SELECT peer_key,afi,safi,filtered,state,
 CASE WHEN octet_length(peer_identity::text)<=$4 THEN peer_identity ELSE NULL END,
 valid_until,row_count,(SELECT count(*) FROM bgp_routing_entries e WHERE e.tenant_id=v.tenant_id AND e.context_id=v.context_id AND e.view_id=v.id AND e.generation=v.generation)
 FROM bgp_routing_views v WHERE tenant_id=$1 AND context_id=$2 AND public_snapshot_id=$3
 AND source_kind='public_bgp' AND collector_agent_id=$5 AND source_ref=$6 AND sender_serial=$7
 ORDER BY peer_key,afi,safi`, source.TenantID, source.ContextID, id, profile.MemoryBytes/32, source.CollectorAgentID, source.SourceRef, source.SenderSerial)
	if err != nil {
		return err
	}
	defer rows.Close()
	remaining := profile
	definitions := make([]BGPRoutingViewDefinition, 0)
	for rows.Next() {
		var key, raw []byte
		var afi uint16
		var safi uint8
		var filtered bool
		var state string
		var declared, actual int64
		var until time.Time
		if err := rows.Scan(&key, &afi, &safi, &filtered, &state, &raw, &until, &declared, &actual); err != nil {
			return err
		}
		if raw == nil {
			return ErrBGPRoutingBudget
		}
		if err := routingBatchPopulationCharge(&remaining, len(raw), 32, 32); err != nil {
			return err
		}
		if err := routingBatchCharge(&remaining, 2048, 512); err != nil {
			return err
		}
		if len(key) != 32 || filtered || state != "staging" || declared != actual || !until.Equal(header.until) {
			return ErrBGPRoutingView
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var peer BGPPublicRoutingPeer
		if decoder.Decode(&peer) != nil {
			return ErrBGPRoutingView
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF || peer.CollectorObservedUnixNanos == nil || *peer.CollectorObservedUnixNanos != header.observedNanos {
			return ErrBGPRoutingView
		}
		definition := BGPRoutingViewDefinition{Kind: "public_bgp", AFI: afi, SAFI: safi, Public: &peer}
		_, expected, err := publicRoutingViewMetadata(ctx, definition, remaining)
		if err != nil {
			return err
		}
		if !bytes.Equal(expected[:], key) {
			return ErrBGPRoutingView
		}
		definitions = append(definitions, definition)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if int64(len(definitions)) != header.expectedViews {
		return ErrBGPRoutingView
	}
	input := BGPPublicSnapshotInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef, ObservationID: id, ObservedAt: time.Unix(0, header.observedNanos), SourceObservedUnixNanos: header.sourceClock, Definitions: definitions}
	_, digest, _, err := preparePublicSnapshot(ctx, input, remaining)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest[:], header.manifestDigest) {
		return ErrBGPRoutingView
	}
	return nil
}
