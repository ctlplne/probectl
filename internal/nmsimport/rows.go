// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"math"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// SealedRow exposes only the normalized capture vocabulary. It is source
// inventory for an authorized dry run, not an action assignment or approval.
// Raw vendor JSON, credentials and alert expressions have no stored column.
type SealedRow struct {
	Number        int64    `json:"row_number"`
	Kind          string   `json:"object_kind"`
	ExternalID    string   `json:"external_id"`
	Label         string   `json:"label,omitempty"`
	Address       string   `json:"address,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	ParentID      string   `json:"parent_external_id,omitempty"`
	LocationID    string   `json:"location_id,omitempty"`
	LocationLabel string   `json:"location_label,omitempty"`
	GroupIDs      []string `json:"group_ids"`
	PollSeconds   int64    `json:"poll_seconds,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	UnmappedCodes []string `json:"unmapped_codes"`
}

// SealedRowsPage is a bounded page from one inert plan snapshot.
type SealedRowsPage struct {
	ContextID    string      `json:"context_id"`
	PlanID       string      `json:"plan_id"`
	SnapshotHash string      `json:"snapshot_hash"`
	RowCount     int64       `json:"row_count"`
	Items        []SealedRow `json:"items"`
	NextCursor   *int64      `json:"next_cursor,omitempty"`
}

// ListSealedRows pages one inert, complete capture after FORCE-RLS plan and
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
		if meta.state != "sealed" {
			return ErrPlanUnavailable
		}
		page.SnapshotHash, page.RowCount = meta.snapshotHash, meta.rowCount
		rows, err := sc.Q.Query(ctx, `SELECT row_number,object_kind,external_id,
			coalesce(label,''),coalesce(address,''),coalesce(hostname,''),
			coalesce(parent_external_id,''),coalesce(location_id,''),coalesce(location_label,''),
			group_ids,coalesce(poll_seconds,0),coalesce(severity,''),unmapped_codes
			FROM nms_import_rows WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			AND row_number>$4 ORDER BY row_number LIMIT $5`,
			sc.Tenant.String(), contextID, planID, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item SealedRow
			if err := rows.Scan(&item.Number, &item.Kind, &item.ExternalID,
				&item.Label, &item.Address, &item.Hostname, &item.ParentID,
				&item.LocationID, &item.LocationLabel, &item.GroupIDs,
				&item.PollSeconds, &item.Severity, &item.UnmappedCodes); err != nil {
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
