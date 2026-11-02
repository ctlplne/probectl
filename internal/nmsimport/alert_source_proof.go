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
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type appliedAlertRuleProof struct {
	tenantID, contextID, planID, sourceID string
	snapshotHash, reviewHash              string
	configVersion                         int64
	verifiedAt                            time.Time
	meta                                  captureMeta
	startPage, endPage, startRow, endRow  int64
}

// verifyAppliedLibreNMSRules re-reads only the fixed rules endpoint after
// inventory apply. Every redacted normalized page must match its captured
// receipt. It returns no source expression, query or delivery operation.
// The caller consumes the proof immediately in a tenant transaction that
// rechecks source version, plan and exact operator-owned target.
func (s CaptureStore) verifyAppliedLibreNMSRules(ctx context.Context,
	contextID, planID, snapshotHash, ruleID string,
	policy LibreNMSFetchPolicy) (appliedAlertRuleProof, error) {
	if s.pool == nil || s.audit == nil || !canonicalSourceNumber(ruleID) ||
		len(snapshotHash) != 64 || !lowerHex(snapshotHash) {
		return appliedAlertRuleProof{}, ErrPlanUnavailable
	}
	contextID, planID, err := reviewPlanIDs(contextID, planID)
	if err != nil {
		return appliedAlertRuleProof{}, err
	}
	proof := appliedAlertRuleProof{contextID: contextID, planID: planID,
		snapshotHash: snapshotHash}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		proof.tenantID = sc.Tenant.String()
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, false)
		if err != nil {
			return err
		}
		if meta.source != LibreNMS || meta.configVersion == 0 ||
			meta.state != "applied" || meta.snapshotHash != snapshotHash {
			return ErrPlanUnavailable
		}
		proof.meta, proof.configVersion = meta, meta.configVersion
		var ruleExists bool
		err = sc.Q.QueryRow(ctx, `SELECT p.source_id::text,p.review_hash,
			EXISTS (SELECT 1 FROM nms_import_rows r
			 WHERE r.tenant_id=p.tenant_id AND r.context_id=p.context_id
			   AND r.plan_id=p.id AND r.object_kind='alert_rule'
			   AND r.external_id=$4 AND r.parent_external_id IS NOT NULL
			   AND r.action='unmapped' AND r.state='skipped')
			FROM nms_import_plans p WHERE p.tenant_id=$1 AND p.context_id=$2
			  AND p.id=$3`, proof.tenantID, contextID, planID, ruleID).
			Scan(&proof.sourceID, &proof.reviewHash, &ruleExists)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		if err != nil {
			return err
		}
		if !ruleExists || len(proof.reviewHash) != 64 {
			return ErrPlanUnavailable
		}
		err = sc.Q.QueryRow(ctx, `SELECT start_page,end_page,start_row,end_row
			FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND resource_kind='rules' AND group_external_id='' AND verified_at IS NOT NULL`,
			proof.tenantID, contextID, planID).
			Scan(&proof.startPage, &proof.endPage, &proof.startRow, &proof.endRow)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		return err
	})
	if err != nil {
		return appliedAlertRuleProof{}, err
	}
	body, err := s.openAppliedLibreNMSRules(ctx, contextID, planID,
		proof.reviewHash, policy)
	if err != nil {
		return appliedAlertRuleProof{}, err
	}
	defer body.Close()
	page, row := proof.startPage, proof.startRow
	err = streamLibreNMSRules(body, func(snapshot Snapshot) error {
		if page >= proof.endPage || row > math.MaxInt64-int64(len(snapshot.Rows)) {
			return ErrSourceDrift
		}
		rows, err := normalizePlanPage(proof.tenantID, contextID,
			proof.meta.instance, proof.meta.generation, LibreNMS, snapshot, row)
		if err != nil {
			return ErrSourceDrift
		}
		hash, err := normalizedPageHash(proof.tenantID, contextID,
			proof.meta.instance, proof.meta.generation, LibreNMS,
			proof.meta.policy, "rules", page, row, rows)
		if err != nil {
			return ErrSourceDrift
		}
		if err := s.compareAppliedAlertRulePage(ctx, proof, page, row,
			int64(len(rows)), hash); err != nil {
			return err
		}
		page++
		row += int64(len(rows))
		return nil
	})
	if err != nil {
		return appliedAlertRuleProof{}, err
	}
	if page != proof.endPage || row != proof.endRow {
		return appliedAlertRuleProof{}, ErrSourceDrift
	}
	proof.verifiedAt = time.Now().UTC()
	return proof, nil
}

func (s CaptureStore) compareAppliedAlertRulePage(ctx context.Context,
	proof appliedAlertRuleProof, page, row, count int64, hash string) error {
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, proof.contextID, proof.planID, false)
		if err != nil {
			return err
		}
		if meta.state != "applied" ||
			meta.snapshotHash != proof.snapshotHash ||
			meta.configVersion != proof.configVersion {
			return ErrPlanUnavailable
		}
		var resource, storedHash string
		var firstRow, rowCount int64
		err = sc.Q.QueryRow(ctx, `SELECT resource_kind,first_row,row_count,page_hash
			FROM nms_import_pages WHERE tenant_id=$1 AND context_id=$2
			  AND plan_id=$3 AND page_number=$4`, proof.tenantID,
			proof.contextID, proof.planID, page).
			Scan(&resource, &firstRow, &rowCount, &storedHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSourceDrift
		}
		if err != nil {
			return err
		}
		if resource != "rules" || firstRow != row || rowCount != count || storedHash != hash {
			return ErrSourceDrift
		}
		return nil
	})
}
