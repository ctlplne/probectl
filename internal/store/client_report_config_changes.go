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

// Shared projection uses only IDs, hashes and binding metadata. Config content
// stays in its separately authorized archive, including on paged timeline reads.
const configChangeProjectionSQL = ` SELECT current.id::text,current.tenant_id::text,current.device,current.version,current.content_hash,current.previous_hash,
 previous.id::text AS previous_id,previous.version AS previous_version,
 COALESCE(NULLIF(current.observed_at,'0001-01-01 00:00:00+00'::timestamptz),current.archived_at) AS occurred_at,current.archived_at,
 CASE WHEN current.entity_context_id IS NULL THEN NULL ELSE jsonb_build_object(
 'kind','operator_bound_archive','context_id',current.entity_context_id,'device_entity_id',current.device_entity_id,'agent_id',current.binding_agent_id,'source_ref',current.binding_source_ref,
 'source_assigned_at',current.binding_source_assigned_at,'agent_assigned_at',current.binding_agent_assigned_at,'bound_at',current.bound_at) END AS binding
 FROM device_configs current JOIN device_configs previous
 ON previous.tenant_id=current.tenant_id AND previous.version=current.version-1
 AND ((current.entity_context_id IS NULL AND previous.entity_context_id IS NULL AND previous.device=current.device)
 OR (previous.entity_context_id,previous.device_entity_id,previous.binding_agent_id,previous.binding_source_ref,previous.binding_source_assigned_at,previous.binding_agent_assigned_at)=
 (current.entity_context_id,current.device_entity_id,current.binding_agent_id,current.binding_source_ref,current.binding_source_assigned_at,current.binding_agent_assigned_at))
 AND previous.content_hash=current.previous_hash
 WHERE current.tenant_id=$1 AND previous.tenant_id=$1 AND current.drifted AND current.version>1
 AND current.content<>'' AND previous.content<>'' AND current.content_hash<>'' AND current.previous_hash<>''
 AND COALESCE(NULLIF(current.observed_at,'0001-01-01 00:00:00+00'::timestamptz),current.archived_at)>=$2
 AND COALESCE(NULLIF(current.observed_at,'0001-01-01 00:00:00+00'::timestamptz),current.archived_at)<$3`

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
`+configChangeProjectionSQL+`
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
		item, err := decodeProjectedConfigChange(body, bound.String())
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeProjectedConfigChange(body []byte, tenant string) (change.Event, error) {
	var item struct {
		ID              string                         `json:"id"`
		TenantID        string                         `json:"tenant_id"`
		Device          string                         `json:"device"`
		Version         int                            `json:"version"`
		ContentHash     string                         `json:"content_hash"`
		PreviousHash    string                         `json:"previous_hash"`
		PreviousID      string                         `json:"previous_id"`
		PreviousVersion int                            `json:"previous_version"`
		OccurredAt      time.Time                      `json:"occurred_at"`
		ArchivedAt      time.Time                      `json:"archived_at"`
		Binding         *change.ConfigBindingReference `json:"binding"`
	}
	if err := json.Unmarshal(body, &item); err != nil {
		return change.Event{}, err
	}
	if item.TenantID != tenant {
		return change.Event{}, entity.ErrScopeMismatch
	}
	return change.Event{ID: "device-config:" + item.ID, TenantID: item.TenantID, Source: "probectl-device-config", Kind: change.KindConfig,
		Title: fmt.Sprintf("Config drift detected on %s", item.Device), Summary: fmt.Sprintf("Redacted device config changed from version %d to %d.", item.PreviousVersion, item.Version), Target: item.Device, Ref: item.ID,
		Config: &change.ConfigReference{CurrentID: item.ID, CurrentVersion: item.Version, CurrentHash: item.ContentHash, PreviousID: item.PreviousID, PreviousVersion: item.PreviousVersion, PreviousHash: item.PreviousHash, Binding: item.Binding}, OccurredAt: item.OccurredAt.UTC(), ReceivedAt: item.ArchivedAt.UTC()}, nil
}
