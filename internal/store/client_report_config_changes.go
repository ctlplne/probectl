// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ClientReportConfigChangesInScope projects every archived configuration drift
// in the report interval, including predecessors outside that interval. Both
// sides are tenant-scoped at storage. Erased content and missing/mismatched
// predecessors cannot attest a drift. No config content is fetched or copied;
// reports retain the same IDs/hashes as the ordinary change projection.
func (ChangeEvents) ClientReportConfigChangesInScope(ctx context.Context, sc tenancy.Scope, from, to time.Time, maxBytes int64) ([]change.Event, error) {
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
 SELECT current.id::text,current.tenant_id::text,current.device,current.version,current.content_hash,current.previous_hash,
 previous.id::text AS previous_id,previous.version AS previous_version,
 COALESCE(NULLIF(current.observed_at,'0001-01-01 00:00:00+00'::timestamptz),current.archived_at) AS occurred_at,current.archived_at
 FROM device_configs current JOIN device_configs previous
 ON previous.tenant_id=current.tenant_id AND previous.device=current.device AND previous.version=current.version-1
 AND previous.content_hash=current.previous_hash
 WHERE current.tenant_id=$1 AND previous.tenant_id=$1 AND current.drifted AND current.version>1
 AND current.content<>'' AND previous.content<>'' AND current.content_hash<>'' AND current.previous_hash<>''
 AND COALESCE(NULLIF(current.observed_at,'0001-01-01 00:00:00+00'::timestamptz),current.archived_at)>=$2
 AND COALESCE(NULLIF(current.observed_at,'0001-01-01 00:00:00+00'::timestamptz),current.archived_at)<$3
 ORDER BY occurred_at,current.id LIMIT $5) projected) documents
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
		var item struct {
			ID              string    `json:"id"`
			TenantID        string    `json:"tenant_id"`
			Device          string    `json:"device"`
			Version         int       `json:"version"`
			ContentHash     string    `json:"content_hash"`
			PreviousHash    string    `json:"previous_hash"`
			PreviousID      string    `json:"previous_id"`
			PreviousVersion int       `json:"previous_version"`
			OccurredAt      time.Time `json:"occurred_at"`
			ArchivedAt      time.Time `json:"archived_at"`
		}
		if err := json.Unmarshal(body, &item); err != nil {
			return nil, err
		}
		if item.TenantID != bound.String() {
			return nil, entity.ErrScopeMismatch
		}
		out = append(out, change.Event{ID: "device-config:" + item.ID, TenantID: item.TenantID, Source: "probectl-device-config", Kind: change.KindConfig,
			Title: fmt.Sprintf("Config drift detected on %s", item.Device), Summary: fmt.Sprintf("Redacted device config changed from version %d to %d.", item.PreviousVersion, item.Version), Target: item.Device, Ref: item.ID,
			Config: &change.ConfigReference{CurrentID: item.ID, CurrentVersion: item.Version, CurrentHash: item.ContentHash, PreviousID: item.PreviousID, PreviousVersion: item.PreviousVersion, PreviousHash: item.PreviousHash}, OccurredAt: item.OccurredAt.UTC(), ReceivedAt: item.ArchivedAt.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
