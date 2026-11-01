// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Seal verifies every committed page against its receipt, folds the stored
// normalized rows into one tenant/source-bound hash, and stops further page
// capture. The sealed state is inert: a separate tenant-authorized preview
// step must decide actions before any apply is possible. The caller supplies
// the page and row totals observed at the end of a complete source capture.
func (s CaptureStore) Seal(ctx context.Context, contextID, planID string,
	expectedPages, expectedRows int64) (string, error) {
	if s.pool == nil || s.audit == nil {
		return "", ErrCaptureAuditUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil || expectedPages < 1 || expectedRows < 0 {
		return "", ErrInvalidPage
	}
	planUUID, err := uuid.Parse(planID)
	if err != nil || planUUID == uuid.Nil {
		return "", ErrInvalidPage
	}
	contextID, planID = contextUUID.String(), planUUID.String()
	var sealedHash string
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantUUID, err := uuid.Parse(sc.Tenant.String())
		if err != nil || tenantUUID == uuid.Nil {
			return ErrPlanUnavailable
		}
		tenantID := tenantUUID.String()
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.state != "capturing" && meta.state != "sealed" {
			return ErrPlanUnavailable
		}
		// Reject fabricated totals before walking pages. A caller must not be
		// able to turn a single captured page into an unbounded query loop.
		var pageTotal, rowTotal int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_pages
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			tenantID, contextID, planID).Scan(&pageTotal); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			tenantID, contextID, planID).Scan(&rowTotal); err != nil {
			return err
		}
		if pageTotal != expectedPages || rowTotal != expectedRows {
			return ErrInvalidPage
		}
		digest, err := newPlanDigest(tenantID, contextID, meta.instance,
			meta.generation, meta.source, meta.policy)
		if err != nil {
			return ErrInvalidPage
		}
		var nextRow int64
		for pageNumber := int64(0); pageNumber < expectedPages; pageNumber++ {
			var resource, pageHash string
			var firstRow, rowCount int64
			err := sc.Q.QueryRow(ctx, `SELECT resource_kind,first_row,row_count,page_hash
				FROM nms_import_pages WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND page_number=$4`,
				tenantID, contextID, planID, pageNumber).
				Scan(&resource, &firstRow, &rowCount, &pageHash)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidPage
			}
			if err != nil {
				return err
			}
			if firstRow != nextRow || rowCount < 0 || rowCount > maxCaptureRowsPerPage ||
				nextRow > math.MaxInt64-rowCount || !knownResource(meta.source, resource) {
				return ErrInvalidPage
			}
			rows, err := readNormalizedPage(ctx, sc, tenantID, contextID, planID, firstRow, rowCount)
			if err != nil {
				return err
			}
			actual, err := normalizedPageHash(tenantID, contextID, meta.instance,
				meta.generation, meta.source, meta.policy, resource, pageNumber, firstRow, rows)
			if err != nil || actual != pageHash || digest.appendPage(rows) != nil {
				return ErrInvalidPage
			}
			nextRow += rowCount
		}
		if nextRow != expectedRows {
			return ErrInvalidPage
		}
		sealedHash, err = digest.hexSum()
		if err != nil {
			return err
		}
		if meta.state == "sealed" {
			if meta.snapshotHash != sealedHash || meta.rowCount != expectedRows {
				return ErrInvalidPage
			}
			return nil
		}
		updated, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET snapshot_hash=$4,row_count=$5,
			state='sealed',capture_lease_hash=NULL,capture_lease_until=NULL
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND state='capturing'`,
			tenantID, contextID, planID, sealedHash, expectedRows)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return ErrPlanUnavailable
		}
		return s.audit(ctx, sc, "nms_import.capture_sealed", planID,
			map[string]any{"context_id": contextID, "snapshot_hash": sealedHash,
				"page_count": expectedPages, "row_count": expectedRows})
	})
	if err != nil {
		return "", err
	}
	return sealedHash, nil
}

func readNormalizedPage(ctx context.Context, sc tenancy.Scope,
	tenantID, contextID, planID string, firstRow, rowCount int64) ([]planRow, error) {
	if rowCount == 0 {
		return nil, nil
	}
	rows, err := sc.Q.Query(ctx, `SELECT row_number,object_kind,external_id,
		coalesce(label,''),coalesce(address,''),coalesce(hostname,''),
		coalesce(parent_external_id,''),coalesce(location_id,''),coalesce(location_label,''),
		group_ids,coalesce(poll_seconds,0),coalesce(severity,''),unmapped_codes
		FROM nms_import_rows
		WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND row_number >= $4 AND row_number < $5
		ORDER BY row_number`, tenantID, contextID, planID, firstRow, firstRow+rowCount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]planRow, 0, rowCount)
	for rows.Next() {
		var row planRow
		if err := rows.Scan(&row.RowNumber, &row.ObjectKind, &row.ExternalID,
			&row.Label, &row.Address, &row.Hostname, &row.ParentID,
			&row.LocationID, &row.LocationLabel, &row.GroupIDs, &row.PollSeconds,
			&row.Severity, &row.UnmappedCodes); err != nil {
			return nil, err
		}
		if len(row.GroupIDs) == 0 {
			row.GroupIDs = nil
		}
		if len(row.UnmappedCodes) == 0 {
			row.UnmappedCodes = nil
		}
		row.ReviewOnly = len(row.UnmappedCodes) > 0
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if int64(len(out)) != rowCount {
		return nil, ErrInvalidPage
	}
	return out, nil
}
