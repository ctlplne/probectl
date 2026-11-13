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

// ClientReportChangesInScope reads the whole selected half-open report window.
// The interactive timeline's page size is not a report population limit.
// Historical labels/attributes confer no current source or device authority.
func (ChangeEvents) ClientReportChangesInScope(ctx context.Context, sc tenancy.Scope, from, to time.Time, maxBytes int64) ([]change.Event, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if from.IsZero() || !to.After(from) {
		return nil, entity.ErrInvalidClaim
	}
	if maxBytes < 4096 {
		return nil, ErrClientReportBudget
	}
	rows, err := sc.Q.Query(ctx, `SELECT CASE WHEN octet_length(body)<=$4::bigint/8 THEN body END
 FROM (SELECT projected.*,row_to_json(projected)::text AS body FROM (
 SELECT `+changeCols+` FROM change_events
 WHERE tenant_id=$1 AND occurred_at>=$2 AND occurred_at<$3
 ORDER BY occurred_at,id LIMIT $5) projected) documents
 ORDER BY occurred_at,id`, bound.String(), from, to, maxBytes, maxBytes/2048+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []change.Event{}
	remaining := maxBytes
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
			return nil, ErrClientReportBudget
		}
		remaining -= cost
		var value change.Event
		if err := json.Unmarshal(body, &value); err != nil {
			return nil, err
		}
		if value.TenantID != bound.String() {
			return nil, entity.ErrScopeMismatch
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}
