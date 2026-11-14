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
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// IncidentRoutingChangesInScope selects complete original owned-router history
// for canonical incident members and affected prefixes. Neither a display name
// nor prefix similarity alone supplies a router or current source grant.
func (ChangeEvents) IncidentRoutingChangesInScope(ctx context.Context, sc tenancy.Scope, inputs *IncidentImpactInputs, prefixes []netip.Prefix, from, to time.Time, memory int64, authorize RoutingChangeAuthorizer) ([]change.Event, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || inputs == nil || inputs.TenantID != bound.String() {
		return nil, entity.ErrScopeMismatch
	}
	if from.IsZero() || !to.After(from) || authorize == nil {
		return nil, entity.ErrInvalidClaim
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	if memory < 4096 || int64(len(inputs.Entities))+int64(len(prefixes)) > memory/2048 {
		return nil, ErrBGPRoutingBudget
	}
	members, err := json.Marshal(inputs.Entities)
	if err != nil {
		return nil, err
	}
	networks := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return nil, entity.ErrInvalidClaim
		}
		networks = append(networks, prefix.String())
	}
	out := []change.Event{}
	if len(inputs.Entities) == 0 || len(networks) == 0 {
		return out, ctx.Err()
	}
	rows, err := sc.Q.Query(ctx, `WITH selected AS (
 SELECT `+changeCols+` FROM change_events
 WHERE tenant_id=$1 AND source=$2 AND kind='route' AND routing IS NOT NULL
 AND occurred_at>=$3 AND occurred_at<$4
 AND EXISTS (SELECT 1 FROM jsonb_to_recordset($5::jsonb) AS member("ContextID" text,"EntityID" text)
  WHERE routing->>'context_id'=member."ContextID" AND routing->>'router_id'=member."EntityID")
 AND EXISTS (SELECT 1 FROM unnest($6::text[]) AS affected(prefix) WHERE change_events.prefix::cidr && affected.prefix::cidr)
 ) SELECT CASE WHEN octet_length(row_to_json(original)::text)::bigint<=$7::bigint/16 THEN row_to_json(original)::text END
 FROM selected original ORDER BY occurred_at,id`, bound.String(), ownedRoutingChangeSource, from.Truncate(time.Microsecond), to, members, networks, memory)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	remaining := memory / 2
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		cost := int64(2048) + 8*int64(len(body))
		if len(body) == 0 || cost > remaining {
			return nil, ErrBGPRoutingBudget
		}
		remaining -= cost
		var event change.Event
		if err := json.Unmarshal(body, &event); err != nil {
			return nil, err
		}
		if event.TenantID != bound.String() {
			return nil, entity.ErrScopeMismatch
		}
		if event.Routing == nil || event.Routing.Validate() != nil {
			return nil, change.ErrRouteReference
		}
		// PostgreSQL's index is quantized. The retained original clock alone
		// determines membership in an explicit nanosecond window.
		at := event.Routing.ObservedAt
		if at.Before(from) || !at.Before(to) {
			continue
		}
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := (ChangeEvents{}).VerifyRoutingChangeReferencesInScope(ctx, sc, out, memory/2, authorize); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}
