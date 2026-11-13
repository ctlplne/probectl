// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrClientReportBudget = errors.New("complete client report inputs exceed admitted memory")

// ClientReportIncidentsInScope keeps every incident that started or remained
// active in the selected half-open month. It supplies no source-read authority:
// callers must authorize each current canonical member before assembling a
// report. The ordinary incident-room page size is not a monthly-report limit.
func (Incidents) ClientReportIncidentsInScope(ctx context.Context, sc tenancy.Scope, from, to time.Time, maxBytes int64) ([]incident.Incident, error) {
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
	rows, err := sc.Q.Query(ctx, `SELECT CASE WHEN octet_length(body)<=$4::bigint/4 THEN body END
 FROM (SELECT projected.*,row_to_json(projected)::text AS body FROM (
 SELECT `+incidentCols+` FROM incidents
 WHERE tenant_id=$1 AND started_at<$3
 AND (started_at>=$2 OR resolved_at IS NULL OR resolved_at>$2)
 ORDER BY started_at,id LIMIT $5) projected) documents
 ORDER BY started_at,id`, bound.String(), from, to, maxBytes, maxBytes/1024+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []incident.Incident{}
	remaining := maxBytes
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		cost := int64(1024) + 4*int64(len(body))
		if len(body) == 0 || cost > remaining {
			return nil, ErrClientReportBudget
		}
		remaining -= cost
		var value struct {
			incident.Incident
			ContextID string `json:"entity_context_id"`
			EntityID  string `json:"entity_id"`
			Attempted bool   `json:"identity_lookup_attempted"`
		}
		if err := json.Unmarshal(body, &value); err != nil {
			return nil, err
		}
		if value.TenantID != bound.String() {
			return nil, entity.ErrScopeMismatch
		}
		value.IdentityContextID, value.IdentityEntityID, value.IdentityLookupAttempted = value.ContextID, value.EntityID, value.Attempted
		out = append(out, value.Incident)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}
