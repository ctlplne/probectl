// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"io"
	"math"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type liveStageReceipt struct {
	startPage int64
	endPage   int64
	startRow  int64
	endRow    int64
}

// The verification pass re-reads one complete endpoint and compares its
// normalized redacted chunks with the first pass. It never copies new rows.
func (s CaptureStore) verifyConfiguredLibreNMSStage(ctx context.Context,
	contextID, planID string, step LiveCaptureStep, resource string, body io.Reader,
	tenantID string, meta captureMeta) (LiveCaptureProgress, error) {
	stream := liveLibreNMSStream(resource, step.GroupID)
	if stream == nil {
		return LiveCaptureProgress{}, ErrPlanUnavailable
	}
	var receipt liveStageReceipt
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var verified bool
		err := sc.Q.QueryRow(ctx, `SELECT start_page,end_page,start_row,end_row,
			verified_at IS NOT NULL FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND resource_kind=$4 AND group_external_id=$5`,
			tenantID, contextID, planID, resource, step.GroupID).
			Scan(&receipt.startPage, &receipt.endPage, &receipt.startRow,
				&receipt.endRow, &verified)
		if errors.Is(err, pgx.ErrNoRows) || verified {
			return ErrPlanUnavailable
		}
		return err
	})
	if err != nil {
		return LiveCaptureProgress{}, err
	}
	page, row := receipt.startPage, receipt.startRow
	err = stream(body, func(snapshot Snapshot) error {
		if page >= receipt.endPage || row > math.MaxInt64-int64(len(snapshot.Rows)) {
			return ErrInvalidPage
		}
		rows, err := normalizePlanPage(tenantID, contextID, meta.instance,
			meta.generation, meta.source, snapshot, row)
		if err != nil {
			return ErrInvalidPage
		}
		hash, err := normalizedPageHash(tenantID, contextID, meta.instance,
			meta.generation, meta.source, meta.policy, resource, page, row, rows)
		if err != nil {
			return ErrInvalidPage
		}
		err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := loadCaptureMeta(ctx, sc, contextID, planID, false)
			if err != nil {
				return err
			}
			if current.source != meta.source || current.instance != meta.instance ||
				current.generation != meta.generation || current.configVersion != meta.configVersion ||
				current.state != "capturing" {
				return ErrPlanUnavailable
			}
			var valid bool
			err = sc.Q.QueryRow(ctx, `SELECT coalesce(capture_lease_hash=$4 AND
				capture_lease_until>clock_timestamp(),false) FROM nms_import_plans
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
				tenantID, contextID, planID, step.leaseHash()).Scan(&valid)
			if err != nil {
				return err
			}
			if !valid {
				return ErrPlanUnavailable
			}
			var storedResource, storedHash string
			var storedFirst, storedRows int64
			err = sc.Q.QueryRow(ctx, `SELECT resource_kind,first_row,row_count,page_hash
				FROM nms_import_pages WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
				  AND page_number=$4`, tenantID, contextID, planID, page).
				Scan(&storedResource, &storedFirst, &storedRows, &storedHash)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidPage
			}
			if err != nil {
				return err
			}
			if storedResource != resource || storedFirst != row ||
				storedRows != int64(len(rows)) || storedHash != hash {
				return ErrInvalidPage
			}
			return nil
		})
		if err != nil {
			return err
		}
		page++
		row += int64(len(rows))
		return nil
	})
	if err != nil || page != receipt.endPage || row != receipt.endRow {
		if err != nil {
			return LiveCaptureProgress{}, err
		}
		return LiveCaptureProgress{}, ErrInvalidPage
	}
	return s.finishConfiguredLibreNMSVerification(ctx, contextID, planID,
		step, resource, receipt)
}

func (s CaptureStore) finishConfiguredLibreNMSVerification(ctx context.Context,
	contextID, planID string, step LiveCaptureStep, resource string,
	receipt liveStageReceipt) (LiveCaptureProgress, error) {
	var result LiveCaptureProgress
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.source != LibreNMS || meta.configVersion == 0 || meta.state != "capturing" {
			return ErrPlanUnavailable
		}
		var stage, groupID, leaseHash string
		var leaseValid bool
		err = sc.Q.QueryRow(ctx, `SELECT capture_stage,capture_group_cursor,
			coalesce(capture_lease_hash,''),coalesce(capture_lease_until>clock_timestamp(),false)
			FROM nms_import_plans WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, planID).
			Scan(&stage, &groupID, &leaseHash, &leaseValid)
		if err != nil {
			return err
		}
		if stage != step.Stage || groupID != step.GroupID ||
			leaseHash != step.leaseHash() || !leaseValid {
			return ErrPlanUnavailable
		}
		updated, err := sc.Q.Exec(ctx, `UPDATE nms_import_capture_steps SET verified_at=clock_timestamp()
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND resource_kind=$4 AND group_external_id=$5
			  AND start_page=$6 AND end_page=$7 AND start_row=$8 AND end_row=$9
			  AND verified_at IS NULL`, sc.Tenant.String(), contextID, planID,
			resource, groupID, receipt.startPage, receipt.endPage,
			receipt.startRow, receipt.endRow)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return ErrPlanUnavailable
		}
		next, nextGroup, err := nextLiveCaptureStage(ctx, sc, contextID, planID, resource, groupID)
		if err != nil {
			return err
		}
		if resource == "rules" {
			next = "complete"
		} else {
			next = "verify_" + next
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_stage=$4,capture_group_cursor=$5,
			capture_lease_hash=NULL,capture_lease_until=NULL
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, planID, next, nextGroup); err != nil {
			return err
		}
		if err := s.audit(ctx, sc, "nms_import.capture_step_verified", planID,
			map[string]any{"context_id": contextID, "stage": resource,
				"group_external_id": groupID}); err != nil {
			return err
		}
		result = LiveCaptureProgress{CompletedStage: step.Stage, NextStage: next,
			Pages: receipt.endPage - receipt.startPage,
			Rows:  receipt.endRow - receipt.startRow}
		return nil
	})
	return result, err
}
