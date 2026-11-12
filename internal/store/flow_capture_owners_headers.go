// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type capturedFlowOwnerHint struct{ agent, router string }

// Bounded identity selectors let the caller authorize each source before any
// private object payload is transferred. They are checked against the decoded,
// hash-verified owner before use; a header alone never grants flow identity.
func loadCapturedFlowOwnerHints(ctx context.Context, sc tenancy.Scope, keys [][]byte) (map[[32]byte]capturedFlowOwnerHint, error) {
	rows, err := sc.Q.Query(ctx, `SELECT receipt.flow_key,
		COALESCE(left(facts.searchable_body#>>'{data,Owner,AgentID}',129),''),
		COALESCE(left(facts.searchable_body#>>'{data,Owner,RouterID}',37),'')
		FROM unnest($2::bytea[]) wanted(key)
		JOIN bgp_flow_capture_receipts receipt ON receipt.tenant_id=$1 AND receipt.flow_key=wanted.key AND receipt.outcome='captured'
		JOIN bgp_flow_capture_payloads links ON (links.tenant_id,links.flow_key)=(receipt.tenant_id,receipt.flow_key)
		JOIN bgp_flow_capture_objects facts ON (facts.tenant_id,facts.digest,facts.kind)=(links.tenant_id,links.facts_digest,'routing_facts')`, pgx.QueryExecModeDescribeExec, sc.Tenant.String(), keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[[32]byte]capturedFlowOwnerHint, len(keys))
	for rows.Next() {
		var raw []byte
		var hint capturedFlowOwnerHint
		if err := rows.Scan(&raw, &hint.agent, &hint.router); err != nil {
			return nil, err
		}
		if len(raw) != 32 {
			return nil, errRoutingCaptureFormat
		}
		key, err := (entity.SourceKey{AgentID: hint.agent, Kind: entity.FlowExporter, SourceRef: "selector"}).Normalize()
		if err != nil || key.AgentID != hint.agent {
			return nil, errRoutingCaptureFormat
		}
		if canonical, err := validRegistryUUID(hint.router); err != nil || canonical != hint.router {
			return nil, errRoutingCaptureFormat
		}
		var id [32]byte
		copy(id[:], raw)
		if _, duplicate := out[id]; duplicate || len(out) >= len(keys) {
			return nil, errRoutingCaptureFormat
		}
		out[id] = hint
	}
	return out, rows.Err()
}
