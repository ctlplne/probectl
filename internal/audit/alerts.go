// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ListAlertWorkflow returns the immutable operator-action receipts for one
// alert fingerprint. The JSON predicate is only a local selector: tenant RLS is
// still the outer boundary and is applied before any row can be returned.
func ListAlertWorkflow(ctx context.Context, s tenancy.Scope, fingerprint string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := s.Q.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at
		   FROM (
		     SELECT seq, actor, action, target, data, prev_hash, hash, created_at
		       FROM audit_events
		      WHERE action IN ('alert.silence', 'alert.acknowledge')
		        AND data->>'fingerprint' = $1
		      ORDER BY seq DESC
		      LIMIT $2
		   ) AS recent
		  ORDER BY seq`, fingerprint, limit)
	if err != nil {
		return nil, fmt.Errorf("list alert workflow audit events: %w", err)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var ev Event
		var data []byte
		if err := rows.Scan(&ev.Seq, &ev.Actor, &ev.Action, &ev.Target, &data,
			&ev.PrevHash, &ev.Hash, &ev.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &ev.Data); err != nil {
			return nil, fmt.Errorf("seq %d: decode alert workflow audit data: %w", ev.Seq, err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
