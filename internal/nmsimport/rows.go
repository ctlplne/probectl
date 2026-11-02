// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// SealedRow exposes normalized source inventory and source-keyed apply status
// for an authorized read. It cannot assign an action or approve a change.
// Raw vendor JSON, credentials and alert expressions have no stored column.
type SealedRow struct {
	Number        int64      `json:"row_number"`
	Kind          string     `json:"object_kind"`
	ExternalID    string     `json:"external_id"`
	Label         string     `json:"label,omitempty"`
	Address       string     `json:"address,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
	ParentID      string     `json:"parent_external_id,omitempty"`
	LocationID    string     `json:"location_id,omitempty"`
	LocationLabel string     `json:"location_label,omitempty"`
	GroupIDs      []string   `json:"group_ids"`
	PollSeconds   int64      `json:"poll_seconds,omitempty"`
	Severity      string     `json:"severity,omitempty"`
	UnmappedCodes []string   `json:"unmapped_codes"`
	Action        string     `json:"action"`
	TargetID      string     `json:"target_entity_id,omitempty"`
	Reviewed      bool       `json:"reviewed"`
	State         string     `json:"state"`
	AppliedAt     *time.Time `json:"applied_at,omitempty"`
	BoundEntityID string     `json:"bound_entity_id,omitempty"`
	BindingPlanID string     `json:"binding_plan_id,omitempty"`
}

// SealedRowsPage is a bounded page from one inert plan snapshot.
type SealedRowsPage struct {
	ContextID    string      `json:"context_id"`
	PlanID       string      `json:"plan_id"`
	SourceID     string      `json:"source_id"`
	SnapshotHash string      `json:"snapshot_hash"`
	RowCount     int64       `json:"row_count"`
	Items        []SealedRow `json:"items"`
	NextCursor   *int64      `json:"next_cursor,omitempty"`
}

// ListSealedRows pages one complete capture after FORCE-RLS plan and
// source-version checks. The authenticated caller supplies the tenant via
// tenancy.WithTenant and must authorize nms.import.read for the context before
// exposing this result at any route. A foreign or stale plan returns one 404.
func (s CaptureStore) ListSealedRows(ctx context.Context, contextID, planID string,
	after int64, limit int) (SealedRowsPage, error) {
	if s.pool == nil || limit < 1 || limit > 100 || after < -1 || after == math.MaxInt64 {
		return SealedRowsPage{}, ErrInvalidPage
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil {
		return SealedRowsPage{}, ErrPlanUnavailable
	}
	planUUID, err := uuid.Parse(planID)
	if err != nil || planUUID == uuid.Nil {
		return SealedRowsPage{}, ErrPlanUnavailable
	}
	contextID, planID = contextUUID.String(), planUUID.String()
	page := SealedRowsPage{ContextID: contextID, PlanID: planID, Items: []SealedRow{}}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		// Hold the source/plan version until this page has been read. A
		// concurrent disable cannot commit between the version check and row
		// lookup and then leave a stale page looking current.
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.state != "sealed" && meta.state != "preview" &&
			meta.state != "applying" && meta.state != "applied" {
			return ErrPlanUnavailable
		}
		page.SnapshotHash, page.RowCount = meta.snapshotHash, meta.rowCount
		if err := sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, planID).Scan(&page.SourceID); err != nil {
			return err
		}
		rows, err := sc.Q.Query(ctx, `SELECT r.row_number,r.object_kind,r.external_id,
			coalesce(r.label,''),coalesce(r.address,''),coalesce(r.hostname,''),
			coalesce(r.parent_external_id,''),coalesce(r.location_id,''),coalesce(r.location_label,''),
			r.group_ids,coalesce(r.poll_seconds,0),coalesce(r.severity,''),r.unmapped_codes,
			r.action,coalesce(r.target_entity_id::text,''),r.reviewed_at IS NOT NULL,
			r.state,r.applied_at,coalesce(v.entity_id::text,''),coalesce(v.plan_id::text,'')
			FROM nms_import_rows r LEFT JOIN nms_import_provenance v ON
			  v.tenant_id=r.tenant_id AND v.context_id=r.context_id
			  AND v.source_id=$6 AND v.object_kind=r.object_kind
			  AND v.external_id=r.external_id
			WHERE r.tenant_id=$1 AND r.context_id=$2 AND r.plan_id=$3
			AND r.row_number>$4 ORDER BY r.row_number LIMIT $5`,
			sc.Tenant.String(), contextID, planID, after, limit+1, page.SourceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item SealedRow
			if err := rows.Scan(&item.Number, &item.Kind, &item.ExternalID,
				&item.Label, &item.Address, &item.Hostname, &item.ParentID,
				&item.LocationID, &item.LocationLabel, &item.GroupIDs,
				&item.PollSeconds, &item.Severity, &item.UnmappedCodes,
				&item.Action, &item.TargetID, &item.Reviewed, &item.State,
				&item.AppliedAt, &item.BoundEntityID, &item.BindingPlanID); err != nil {
				return err
			}
			if len(page.Items) == limit {
				cursor := page.Items[len(page.Items)-1].Number
				page.NextCursor = &cursor
				break
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return SealedRowsPage{}, err
	}
	return page, nil
}
