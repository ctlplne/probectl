// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ChangeTimelinePage keeps both original producers under one stable ordering.
// A page size bounds one response, never the retained history population.
type ChangeTimelinePage struct {
	Events []change.Event
	More   bool
}

func (ChangeEvents) TimelinePageInScope(ctx context.Context, sc tenancy.Scope, from, to, before time.Time, beforeID string, limit int, memory int64) (ChangeTimelinePage, error) {
	none := ChangeTimelinePage{}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return none, entity.ErrScopeMismatch
	}
	if from.IsZero() || !to.After(from) || limit < 1 {
		return none, entity.ErrInvalidClaim
	}
	if memory < 4096 || int64(limit) >= memory/2048 {
		return none, ErrClientReportBudget
	}
	rows, err := sc.Q.Query(ctx, `WITH configs AS (`+configChangeProjectionSQL+`),
 stored_page AS (
 SELECT id::text,occurred_at,row_to_json(original)::jsonb AS body FROM (
 SELECT `+changeCols+` FROM change_events
 WHERE tenant_id=$1 AND occurred_at>=$2 AND occurred_at<$3
 AND ($6='' OR occurred_at<$7 OR (occurred_at=$7 AND id::text>$6))
 ORDER BY occurred_at DESC,id::text LIMIT $4+1) original
 ), config_page AS (
 SELECT 'device-config:'||id AS id,occurred_at,jsonb_build_object(
 'id','device-config:'||id,'tenant_id',tenant_id,'source','probectl-device-config','kind','config',
 'title','Config drift detected on '||device,'summary','Redacted device config changed from version '||previous_version||' to '||version||'.',
 'target',device,'ref',id,'occurred_at',occurred_at,'received_at',archived_at,
 'config',jsonb_build_object('current_id',id,'current_version',version,'current_hash',content_hash,
 'previous_id',previous_id,'previous_version',previous_version,'previous_hash',previous_hash,'binding',binding)) AS body
 FROM configs WHERE $6='' OR occurred_at<$7 OR (occurred_at=$7 AND 'device-config:'||id>$6)
 ORDER BY occurred_at DESC,id LIMIT $4+1
 ), combined AS (SELECT * FROM stored_page UNION ALL SELECT * FROM config_page)
 SELECT CASE WHEN octet_length(body::text)<=$5::bigint/8 THEN body::text END
 FROM combined ORDER BY occurred_at DESC,id LIMIT $4+1`, bound.String(), from, to, limit, memory, beforeID, before)
	if err != nil {
		return none, err
	}
	defer rows.Close()
	page := ChangeTimelinePage{Events: []change.Event{}}
	remaining := memory
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return none, err
		}
		cost := int64(2048) + 8*int64(len(body))
		if len(body) == 0 || cost > remaining {
			return none, ErrClientReportBudget
		}
		remaining -= cost
		var event change.Event
		if err := json.Unmarshal(body, &event); err != nil {
			return none, err
		}
		if event.TenantID != bound.String() {
			return none, entity.ErrScopeMismatch
		}
		if event.Routing != nil {
			if event.Routing.Validate() != nil || event.Source != ownedRoutingChangeSource || event.Kind != change.KindRoute {
				return none, change.ErrRouteReference
			}
		} else if event.Source == ownedRoutingChangeSource {
			return none, change.ErrRouteReference
		}
		if len(page.Events) == limit {
			page.More = true
			continue
		}
		page.Events = append(page.Events, event)
	}
	if err := rows.Err(); err != nil {
		return none, err
	}
	return page, ctx.Err()
}
