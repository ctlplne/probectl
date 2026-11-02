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
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrSourceDrift = errors.New("nmsimport: reviewed source inventory changed")

// ApplyVerificationProgress names only the fixed endpoint and receipt range.
// A complete pass authorizes one bounded destination chunk for 60 seconds;
// the next chunk needs a new pass. LibreNMS offers no atomic generation token.
type ApplyVerificationProgress struct {
	VerifiedStage string `json:"verified_stage"`
	NextStage     string `json:"next_stage"`
	Pages         int64  `json:"pages"`
	Rows          int64  `json:"rows"`
	Ready         bool   `json:"ready"`
}

// VerifyNextConfiguredLibreNMSForApply re-reads one server-selected endpoint
// after review. It makes no destination write. The caller must authorize
// nms.import.write for contextID and supply deployment-owned fetch policy.
func (s CaptureStore) VerifyNextConfiguredLibreNMSForApply(ctx context.Context,
	contextID, planID, snapshotHash, reviewHash string,
	policy LibreNMSFetchPolicy) (ApplyVerificationProgress, error) {
	if s.pool == nil || s.audit == nil {
		return ApplyVerificationProgress{}, ErrCaptureAuditUnavailable
	}
	contextID, planID, err := reviewPlanIDs(contextID, planID)
	if err != nil || len(snapshotHash) != 64 || !lowerHex(snapshotHash) ||
		len(reviewHash) != 64 || !lowerHex(reviewHash) {
		return ApplyVerificationProgress{}, ErrPlanUnavailable
	}
	step, receipt, ready, err := s.acquireApplyVerification(ctx, contextID, planID,
		snapshotHash, reviewHash)
	if err != nil {
		return ApplyVerificationProgress{}, err
	}
	if ready {
		return ApplyVerificationProgress{NextStage: "ready", Ready: true}, nil
	}
	defer step.Zeroize()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = s.releaseApplyVerification(cleanup, contextID, planID, reviewHash, step)
	}()
	resource := step.Stage
	var body io.ReadCloser
	if resource == "memberships" {
		body, err = s.openConfiguredLibreNMS(ctx, contextID, planID,
			"membership", step.GroupID, reviewHash, policy)
	} else {
		body, err = s.openConfiguredLibreNMS(ctx, contextID, planID,
			resource, "", reviewHash, policy)
	}
	if err != nil {
		return ApplyVerificationProgress{}, err
	}
	defer body.Close()
	var meta captureMeta
	var tenantID string
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantID = sc.Tenant.String()
		var readErr error
		meta, readErr = loadCaptureMeta(ctx, sc, contextID, planID, false)
		if readErr != nil {
			return readErr
		}
		if (meta.state != "preview" && meta.state != "applying") ||
			meta.snapshotHash != snapshotHash {
			return ErrPlanUnavailable
		}
		return nil
	})
	if err != nil {
		return ApplyVerificationProgress{}, err
	}
	stream := liveLibreNMSStream(resource, step.GroupID)
	if stream == nil {
		return ApplyVerificationProgress{}, ErrPlanUnavailable
	}
	page, row := receipt.startPage, receipt.startRow
	err = stream(body, func(snapshot Snapshot) error {
		if page >= receipt.endPage || row > math.MaxInt64-int64(len(snapshot.Rows)) {
			return ErrSourceDrift
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
			if current.snapshotHash != snapshotHash ||
				(current.state != "preview" && current.state != "applying") {
				return ErrPlanUnavailable
			}
			var storedResource, storedHash string
			var storedFirst, storedRows int64
			var leaseValid bool
			if err := sc.Q.QueryRow(ctx, `SELECT coalesce(p.capture_lease_hash=$4 AND
				p.capture_lease_until>clock_timestamp(),false),r.resource_kind,
				r.first_row,r.row_count,r.page_hash
				FROM nms_import_plans p JOIN nms_import_pages r
				  ON r.tenant_id=p.tenant_id AND r.context_id=p.context_id
				 AND r.plan_id=p.id
				WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.id=$3
				  AND r.page_number=$5`, tenantID, contextID, planID,
				step.leaseHash(), page).Scan(&leaseValid, &storedResource,
				&storedFirst, &storedRows, &storedHash); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrSourceDrift
				}
				return err
			}
			if !leaseValid {
				return ErrCaptureBusy
			}
			if storedResource != resource || storedFirst != row ||
				storedRows != int64(len(rows)) || storedHash != hash {
				return ErrSourceDrift
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
	if err == nil && (page != receipt.endPage || row != receipt.endRow) {
		err = ErrSourceDrift
	}
	if errors.Is(err, ErrSourceDrift) {
		markCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if staleErr := s.markApplySourceStale(markCtx, contextID, planID, reviewHash, step); staleErr != nil {
			return ApplyVerificationProgress{}, staleErr
		}
	}
	if err != nil {
		return ApplyVerificationProgress{}, err
	}
	return s.finishApplyVerification(ctx, contextID, planID, snapshotHash,
		reviewHash, step, receipt)
}

func (s CaptureStore) acquireApplyVerification(ctx context.Context,
	contextID, planID, snapshotHash, reviewHash string) (LiveCaptureStep, liveStageReceipt, bool, error) {
	secret, err := crypto.Random(32)
	if err != nil {
		return LiveCaptureStep{}, liveStageReceipt{}, false, err
	}
	step := LiveCaptureStep{secret: secret}
	var receipt liveStageReceipt
	var ready bool
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.source != LibreNMS || meta.configVersion == 0 ||
			(meta.state != "preview" && meta.state != "applying") ||
			meta.snapshotHash != snapshotHash {
			return ErrPlanUnavailable
		}
		var frozenHash, stage string
		var enabled, busy, proofReady bool
		if err := sc.Q.QueryRow(ctx, `SELECT p.review_hash,p.capture_stage,s.fetch_enabled,
			coalesce(p.capture_lease_until>clock_timestamp(),false),
			coalesce(p.apply_verified_review_hash=$4 AND
			 p.apply_verified_at>clock_timestamp()-interval '60 seconds',false)
			FROM nms_import_plans p JOIN nms_import_sources s
			  ON s.tenant_id=p.tenant_id AND s.context_id=p.context_id AND s.id=p.source_id
			WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.id=$3`, sc.Tenant.String(),
			contextID, planID, reviewHash).Scan(&frozenHash, &stage, &enabled,
			&busy, &proofReady); err != nil {
			return err
		}
		if frozenHash != reviewHash || stage != "complete" || !enabled {
			return ErrPlanUnavailable
		}
		if proofReady {
			ready = true
			return nil
		}
		if busy {
			return ErrCaptureBusy
		}
		var pending int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND apply_verified_at IS NULL`, sc.Tenant.String(), contextID,
			planID).Scan(&pending); err != nil {
			return err
		}
		if pending == 0 {
			// A completed proof expired without a destination chunk. Start a
			// new complete pass; individual old endpoint reads cannot be reused.
			if _, err := sc.Q.Exec(ctx, `UPDATE nms_import_capture_steps
				SET apply_verified_at=NULL
				WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
				sc.Tenant.String(), contextID, planID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
				apply_verified_review_hash=NULL,apply_verified_at=NULL
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
				sc.Tenant.String(), contextID, planID); err != nil {
				return err
			}
		}
		err = sc.Q.QueryRow(ctx, `SELECT resource_kind,group_external_id,
			start_page,end_page,start_row,end_row
			FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND verified_at IS NOT NULL AND apply_verified_at IS NULL
			ORDER BY start_page LIMIT 1 FOR UPDATE`, sc.Tenant.String(),
			contextID, planID).Scan(&step.Stage, &step.GroupID,
			&receipt.startPage, &receipt.endPage, &receipt.startRow, &receipt.endRow)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		if err != nil {
			return err
		}
		step.StartPage, step.StartRow = receipt.startPage, receipt.startRow
		if _, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_lease_hash=$4,
			capture_lease_until=clock_timestamp()+interval '60 seconds'
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, sc.Tenant.String(),
			contextID, planID, step.leaseHash()); err != nil {
			return err
		}
		return s.audit(ctx, sc, "nms_import.apply_source_step_acquired", planID,
			map[string]any{"context_id": contextID, "resource": step.Stage,
				"group_external_id": step.GroupID})
	})
	if err != nil || ready {
		step.Zeroize()
	}
	return step, receipt, ready, err
}

func (s CaptureStore) releaseApplyVerification(ctx context.Context,
	contextID, planID, reviewHash string, step LiveCaptureStep) error {
	if len(step.secret) != 32 {
		return nil
	}
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		command, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_lease_hash=NULL,capture_lease_until=NULL
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND review_hash=$4
			  AND capture_lease_hash=$5`, sc.Tenant.String(), contextID,
			planID, reviewHash, step.leaseHash())
		if err != nil || command.RowsAffected() == 0 {
			return err
		}
		return s.audit(ctx, sc, "nms_import.apply_source_step_released", planID,
			map[string]any{"context_id": contextID, "resource": step.Stage})
	})
}

func (s CaptureStore) markApplySourceStale(ctx context.Context,
	contextID, planID, reviewHash string, step LiveCaptureStep) error {
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.state != "preview" && meta.state != "applying" {
			return ErrPlanUnavailable
		}
		command, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET state='stale',
			capture_lease_hash=NULL,capture_lease_until=NULL,
			apply_verified_review_hash=NULL,apply_verified_at=NULL
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND review_hash=$4
			  AND capture_lease_hash=$5`, sc.Tenant.String(), contextID, planID,
			reviewHash, step.leaseHash())
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrCaptureBusy
		}
		return s.audit(ctx, sc, "nms_import.apply_source_stale", planID,
			map[string]any{"context_id": contextID, "resource": step.Stage})
	})
}

func (s CaptureStore) finishApplyVerification(ctx context.Context,
	contextID, planID, snapshotHash, reviewHash string, step LiveCaptureStep,
	receipt liveStageReceipt) (ApplyVerificationProgress, error) {
	progress := ApplyVerificationProgress{VerifiedStage: step.Stage,
		Pages: receipt.endPage - receipt.startPage,
		Rows:  receipt.endRow - receipt.startRow}
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.snapshotHash != snapshotHash ||
			(meta.state != "preview" && meta.state != "applying") {
			return ErrPlanUnavailable
		}
		command, err := sc.Q.Exec(ctx, `UPDATE nms_import_capture_steps
			SET apply_verified_at=clock_timestamp()
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND resource_kind=$4 AND group_external_id=$5
			  AND start_page=$6 AND end_page=$7 AND start_row=$8 AND end_row=$9
			  AND verified_at IS NOT NULL AND apply_verified_at IS NULL`,
			sc.Tenant.String(), contextID, planID, step.Stage, step.GroupID,
			receipt.startPage, receipt.endPage, receipt.startRow, receipt.endRow)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrPlanUnavailable
		}
		var total, pending int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE apply_verified_at IS NULL OR verified_at IS NULL)
			FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			sc.Tenant.String(), contextID, planID).Scan(&total, &pending); err != nil {
			return err
		}
		if total == 0 {
			return ErrPlanUnavailable
		}
		progress.Ready = pending == 0
		progress.NextStage = "verify"
		if progress.Ready {
			progress.NextStage = "ready"
		}
		command, err = sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_lease_hash=NULL,capture_lease_until=NULL,
			apply_verified_review_hash=CASE WHEN $6 THEN $4 ELSE NULL END,
			apply_verified_at=CASE WHEN $6 THEN clock_timestamp() ELSE NULL END
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND review_hash=$4
			  AND capture_lease_hash=$5 AND capture_lease_until>clock_timestamp()`,
			sc.Tenant.String(), contextID, planID, reviewHash,
			step.leaseHash(), progress.Ready)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrCaptureBusy
		}
		return s.audit(ctx, sc, "nms_import.apply_source_step_verified", planID,
			map[string]any{"context_id": contextID, "resource": step.Stage,
				"group_external_id": step.GroupID, "ready": progress.Ready})
	})
	if err != nil {
		return ApplyVerificationProgress{}, err
	}
	return progress, nil
}
