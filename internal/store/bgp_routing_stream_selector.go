// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"strconv"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// The authenticated source and current stored generation have already resolved
// canonical ownership. Packet selectors can only reject that selection, never
// replace it or grant another tenant, context, router or serializer profile.
func routingStreamSelectorMatches(source BGPRoutingSource, peer *BGPRoutingPeer) error {
	if peer == nil {
		return nil
	} // payload-free authenticated generation reset
	if peer.Type != 3 || !peer.BGPIdentifier.Is4() {
		return ErrBGPRoutingView
	}
	if source.routingSelection == nil {
		if peer.Distinguisher != ([8]byte{}) {
			return ErrBGPRoutingView
		}
		return nil
	}
	binding := source.routingSelection.Binding
	if binding.Distinguisher != hex.EncodeToString(peer.Distinguisher[:]) || binding.BGPIdentifier != peer.BGPIdentifier.String() {
		return ErrBGPRoutingView
	}
	return nil
}

func authorizeRoutingStreamPeer(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, generation string, peer *BGPRoutingPeer) error {
	if peer == nil {
		return nil
	}
	neighbor := ""
	if isGlobalRoutingNeighbor(*peer) {
		neighbor = peer.Address.String()
	} else if err := routingStreamSelectorMatches(source, peer); err != nil {
		return err
	}
	var found bool
	err := sc.Q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4 AND source_ref=$5
 AND sender_serial=$6 AND origin_serial=$7 AND generation=$8 AND source_kind='router_bmp'
 AND (($9='' AND view_kind IN ('loc_rib','operator_loc_rib')) OR
      ($9<>'' AND view_kind='adj_rib_in_post_policy' AND peer_identity->>'Address'=$9
       AND peer_identity->>'ASN'=$10 AND peer_identity->>'BGPIdentifier'=$11)))`,
		source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial,
		source.OriginSerial, generation, neighbor, strconv.FormatUint(uint64(peer.ASN), 10), peer.BGPIdentifier.String()).Scan(&found)
	if err != nil {
		return err
	}
	if !found {
		return ErrBGPRoutingView
	}
	return nil
}
