// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"slices"
	"strings"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Neighbor evidence is an independent source from the selected RIB. Recheck
// it before exposing a retained next-hop ASN; loss of that supporting source
// does not erase the separately authorized immutable route/path evidence.
func redactUnreadableCapturedNextHops(ctx context.Context, sc tenancy.Scope, lookup *BGPRoutingFlowLookup, budget BGPRoutingBudget) error {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, side := range []BGPRoutingFlowSide{lookup.Source, lookup.Destination} {
		for _, hop := range side.NextHops {
			for _, source := range hop.Sources {
				if err := routingBatchCharge(&budget, 256+int64(len(source))*12, 256); err != nil {
					return err
				}
				id, ok := strings.CutPrefix(source, "evidence/")
				if canonical, err := validRegistryUUID(id); !ok || err != nil || canonical != id {
					return errRoutingCaptureFormat
				}
				ids[id] = false
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	slices.Sort(keys)
	rows, err := sc.Q.Query(ctx, `SELECT e.id::text FROM entity_evidence e `+interfaceRoleAuthorityJoinsSQL()+`
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.entity_id=$3
 AND e.source_kind='bmp_peer' AND e.alias_kind='bmp_peer_id'
 AND e.id=ANY($4::uuid[]) AND source.anchor_entity_id=e.entity_id
 AND e.support_evidence_id IS NULL AND `+currentEntityEvidenceSnapshotSQL()+` ORDER BY e.id`,
		sc.Tenant.String(), lookup.Owner.ContextID, lookup.Owner.RouterID, keys)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if _, expected := ids[id]; !expected {
			return errRoutingCaptureFormat
		}
		ids[id] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, side := range []*BGPRoutingFlowSide{&lookup.Source, &lookup.Destination} {
		for i := range side.NextHops {
			hop := &side.NextHops[i]
			for _, source := range hop.Sources {
				if !ids[strings.TrimPrefix(source, "evidence/")] {
					*hop = BGPRoutingNextHopAS{Reason: "current_source_unavailable"}
					break
				}
			}
		}
	}
	return ctx.Err()
}
