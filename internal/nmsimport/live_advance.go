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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// LiveCaptureProgress reports only the server-selected stage and bounded
// receipt range. It never echoes a source URL, credential, raw row or lease.
type LiveCaptureProgress struct {
	CompletedStage string `json:"completed_stage"`
	NextStage      string `json:"next_stage"`
	Pages          int64  `json:"pages"`
	Rows           int64  `json:"rows"`
	SnapshotHash   string `json:"snapshot_hash,omitempty"`
}

// CaptureNextConfiguredLibreNMSStage makes exactly one configured HTTPS
// endpoint request. A complete response advances the cursor; a partial or
// changed retry leaves every written page inert and replays from the stage's
// starting ordinal on the next request.
func (s CaptureStore) CaptureNextConfiguredLibreNMSStage(ctx context.Context,
	contextID, planID string, policy LibreNMSFetchPolicy) (LiveCaptureProgress, error) {
	step, err := s.AcquireConfiguredLibreNMSStage(ctx, contextID, planID)
	if err != nil {
		return LiveCaptureProgress{}, err
	}
	defer step.Zeroize()
	defer func() {
		// Client cancellation must not strand the lease. A lost cleanup is still
		// bounded by the database expiry, but this releases it promptly.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = s.ReleaseConfiguredLibreNMSStage(cleanup, contextID, planID, step)
	}()
	if step.Stage == "complete" {
		hash, err := s.sealCompletedConfiguredLibreNMS(ctx, contextID, planID, step)
		if err != nil {
			return LiveCaptureProgress{}, err
		}
		return LiveCaptureProgress{CompletedStage: "complete", NextStage: "sealed",
			SnapshotHash: hash}, nil
	}
	verify := strings.HasPrefix(step.Stage, "verify_")
	resource := strings.TrimPrefix(step.Stage, "verify_")
	var body io.ReadCloser
	if resource == "memberships" {
		body, err = s.OpenConfiguredLibreNMSMembership(ctx, contextID, planID, step.GroupID, policy)
	} else {
		body, err = s.OpenConfiguredLibreNMS(ctx, contextID, planID, resource, policy)
	}
	if err != nil {
		return LiveCaptureProgress{}, err
	}
	defer body.Close()
	var tenantID string
	var meta captureMeta
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantID = sc.Tenant.String()
		var readErr error
		meta, readErr = loadCaptureMeta(ctx, sc, contextID, planID, false)
		return readErr
	})
	if err != nil {
		return LiveCaptureProgress{}, err
	}
	if meta.source != LibreNMS || meta.state != "capturing" {
		return LiveCaptureProgress{}, ErrPlanUnavailable
	}
	if verify {
		return s.verifyConfiguredLibreNMSStage(ctx, contextID, planID,
			step, resource, body, tenantID, meta)
	}
	page, row := step.StartPage, step.StartRow
	stream := liveLibreNMSStream(resource, step.GroupID)
	if stream == nil {
		return LiveCaptureProgress{}, ErrPlanUnavailable
	}
	err = stream(body, func(snapshot Snapshot) error {
		if page == math.MaxInt64 || row > math.MaxInt64-int64(len(snapshot.Rows)) {
			return ErrInvalidPage
		}
		if _, err := s.appendSnapshot(ctx, contextID, planID, page,
			resource, row, tenantID, meta, snapshot, step.leaseHash()); err != nil {
			return err
		}
		page++
		row += int64(len(snapshot.Rows))
		return nil
	})
	if err != nil {
		return LiveCaptureProgress{}, err
	}
	return s.finishConfiguredLibreNMSStage(ctx, contextID, planID, step, page, row)
}

func (s CaptureStore) sealCompletedConfiguredLibreNMS(ctx context.Context,
	contextID, planID string, step LiveCaptureStep) (string, error) {
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, false)
		if err != nil {
			return err
		}
		if meta.source != LibreNMS || meta.configVersion == 0 || meta.state != "capturing" {
			return ErrPlanUnavailable
		}
		var valid bool
		err = sc.Q.QueryRow(ctx, `SELECT coalesce(capture_lease_hash=$4 AND
			capture_lease_until>clock_timestamp(),false)
			FROM nms_import_plans WHERE tenant_id=$1 AND context_id=$2 AND id=$3
			  AND capture_stage='complete' AND capture_start_page=$5 AND capture_start_row=$6`,
			sc.Tenant.String(), contextID, planID, step.leaseHash(),
			step.StartPage, step.StartRow).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		if err != nil {
			return err
		}
		if !valid {
			return ErrPlanUnavailable
		}
		var total, unverified, groupSteps, rows int64
		err = sc.Q.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE verified_at IS NULL),
			count(*) FILTER (WHERE resource_kind='memberships'),
			coalesce(sum(end_row-start_row),0)
			FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			sc.Tenant.String(), contextID, planID).
			Scan(&total, &unverified, &groupSteps, &rows)
		if err != nil {
			return err
		}
		var groups int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND object_kind='group'`,
			sc.Tenant.String(), contextID, planID).Scan(&groups); err != nil {
			return err
		}
		if total != 4+groups || unverified != 0 || groupSteps != groups ||
			rows != step.StartRow {
			return ErrInvalidPage
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return s.Seal(ctx, contextID, planID, step.StartPage, step.StartRow)
}

func liveLibreNMSStream(stage, groupID string) func(io.Reader, func(Snapshot) error) error {
	switch stage {
	case "devices":
		return streamLibreNMSDevices
	case "locations":
		return streamLibreNMSLocations
	case "groups":
		return streamCapturedLibreNMSGroups
	case "memberships":
		if groupID != "" {
			return func(raw io.Reader, emit func(Snapshot) error) error {
				return streamLibreNMSGroupMembers(raw, groupID, emit)
			}
		}
	case "rules":
		return streamLibreNMSRules
	}
	return nil
}

func (s CaptureStore) finishConfiguredLibreNMSStage(ctx context.Context,
	contextID, planID string, step LiveCaptureStep, endPage, endRow int64) (LiveCaptureProgress, error) {
	if len(step.secret) != 32 || endPage <= step.StartPage || endRow < step.StartRow {
		return LiveCaptureProgress{}, ErrInvalidPage
	}
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
		var startPage, startRow int64
		var leaseValid bool
		err = sc.Q.QueryRow(ctx, `SELECT capture_stage,capture_group_cursor,
			capture_start_page,capture_start_row,coalesce(capture_lease_hash,'') ,
			coalesce(capture_lease_until>clock_timestamp(),false)
			FROM nms_import_plans WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, planID).Scan(&stage, &groupID,
			&startPage, &startRow, &leaseHash, &leaseValid)
		if err != nil {
			return err
		}
		if stage != step.Stage || groupID != step.GroupID || startPage != step.StartPage ||
			startRow != step.StartRow || leaseHash != step.leaseHash() || !leaseValid {
			return ErrPlanUnavailable
		}
		var actualPages, actualRows, lastPage, lastRow int64
		err = sc.Q.QueryRow(ctx, `SELECT count(*),coalesce(sum(row_count),0),
			coalesce(max(page_number),-1),coalesce(max(first_row+row_count),0)
			FROM nms_import_pages
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND page_number >= $4 AND page_number < $5 AND resource_kind=$6`,
			sc.Tenant.String(), contextID, planID, startPage, endPage, stage).
			Scan(&actualPages, &actualRows, &lastPage, &lastRow)
		if err != nil {
			return err
		}
		if actualPages != endPage-startPage || actualRows != endRow-startRow ||
			lastPage != endPage-1 || lastRow != endRow {
			return ErrInvalidPage
		}
		var totalPages int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_pages
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			sc.Tenant.String(), contextID, planID).Scan(&totalPages); err != nil {
			return err
		}
		if totalPages != endPage {
			return ErrInvalidPage
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_capture_steps
			(tenant_id,context_id,plan_id,resource_kind,group_external_id,
			 start_page,end_page,start_row,end_row)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			sc.Tenant.String(), contextID, planID, stage, groupID,
			startPage, endPage, startRow, endRow); err != nil {
			return captureWriteErr(err)
		}
		next, nextGroup, err := nextLiveCaptureStage(ctx, sc, contextID, planID, stage, groupID)
		if err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_stage=$4,capture_group_cursor=$5,capture_start_page=$6,
			capture_start_row=$7,capture_lease_hash=NULL,capture_lease_until=NULL
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, planID, next, nextGroup, endPage, endRow); err != nil {
			return err
		}
		if err := s.audit(ctx, sc, "nms_import.capture_step_completed", planID,
			map[string]any{"context_id": contextID, "stage": stage,
				"group_external_id": groupID, "pages": actualPages, "rows": actualRows}); err != nil {
			return err
		}
		result = LiveCaptureProgress{CompletedStage: stage, NextStage: next,
			Pages: actualPages, Rows: actualRows}
		return nil
	})
	return result, err
}

func nextLiveCaptureStage(ctx context.Context, sc tenancy.Scope,
	contextID, planID, stage, groupID string) (string, string, error) {
	switch stage {
	case "devices":
		return "locations", "", nil
	case "locations":
		return "groups", "", nil
	case "groups", "memberships":
		var next string
		query := `SELECT external_id FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND object_kind='group' AND action='captured'`
		args := []any{sc.Tenant.String(), contextID, planID}
		if stage == "memberships" {
			query += ` AND (octet_length(external_id),external_id) >
				(octet_length($4::text),$4::text)`
			args = append(args, groupID)
		}
		query += ` ORDER BY octet_length(external_id),external_id LIMIT 1`
		err := sc.Q.QueryRow(ctx, query, args...).Scan(&next)
		if errors.Is(err, pgx.ErrNoRows) {
			return "rules", "", nil
		}
		if err != nil {
			return "", "", err
		}
		return "memberships", next, nil
	case "rules":
		return "verify_devices", "", nil
	default:
		return "", "", ErrPlanUnavailable
	}
}
