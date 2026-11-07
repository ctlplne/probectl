// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// One complete Peer Up replaces every overlapping old cohort as a whole.
// Disjoint emulated families of the same source identity remain independent.
// A protocol identity change retires all old cohorts, including omitted AFIs.
// Caller holds the tenant account/source locks and the whole-stage savepoint.
func retireRoutingStageCohorts(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, definitions []BGPRoutingViewDefinition) error {
	if len(definitions) == 0 || len(definitions) > 2 {
		return ErrBGPRoutingView
	}
	families := make([]int16, 0, len(definitions))
	for _, definition := range definitions {
		families = append(families, int16(definition.AFI))
	}
	peer := definitions[0].Peer
	identity, err := json.Marshal(map[string]any{"Type": peer.Type, "Flags": peer.Flags, "Distinguisher": peer.Distinguisher, "ASN": peer.ASN, "BGPIdentifier": peer.BGPIdentifier})
	if err != nil {
		return err
	}
	epoch, bindingID := routingSourceSlot(source)
	_, err = sc.Q.Exec(ctx, `WITH candidates AS MATERIALIZED (
 SELECT id,generation,afi,peer_identity FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4 AND source_ref=$5
 AND source_kind='router_bmp' AND state IN ('staging','current')
 AND ((routing_selection IS NULL AND $6::text IS NULL)
      OR (routing_selection->>'epoch'=$6 AND routing_selection->>'binding_id'=$7)) FOR UPDATE
 ), retiring AS (
 SELECT DISTINCT generation FROM candidates WHERE afi=ANY($8::smallint[]) OR NOT (peer_identity @> $9::jsonb)
 )
 UPDATE bgp_routing_views v SET state='invalid',updated_at=clock_timestamp()
 FROM candidates c WHERE v.tenant_id=$1 AND v.context_id=$2 AND v.router_id=$3 AND v.id=c.id
 AND c.generation IN (SELECT generation FROM retiring)`, source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef, epoch, bindingID, families, string(identity))
	return err
}
