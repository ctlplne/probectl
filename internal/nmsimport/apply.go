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
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ApplyProgress is one committed chunk, never an assertion that an entire
// source inventory was imported. A caller retries with the same two hashes
// until remaining is zero.
type ApplyProgress struct {
	State      string `json:"state"`
	Applied    int    `json:"applied"`
	Skipped    int    `json:"skipped"`
	Remaining  int64  `json:"remaining"`
	RowCount   int64  `json:"row_count"`
	ReviewHash string `json:"review_hash"`
}

type applyRow struct {
	number        int64
	kind          string
	externalID    string
	label         string
	hostname      string
	address       string
	action        string
	targetID      string
	fingerprint   string
	groupRevision int64
	unmapped      []string
	reviewed      bool
}

// ApplyReview writes at most 100 frozen decisions in one tenant transaction.
// The caller must authorize nms.import.write for the selected context. The
// server-selected row order, source/plan locks, exact target fingerprints and
// source-keyed provenance make a retry idempotent; an audit failure rolls the
// whole chunk back. Only explicit device/site label choices can write a
// canonical entity. No imported row can author agent evidence or alerts.
func (s CaptureStore) ApplyReview(ctx context.Context, contextID, planID,
	snapshotHash, reviewHash string) (ApplyProgress, error) {
	if s.pool == nil || s.audit == nil {
		return ApplyProgress{}, ErrCaptureAuditUnavailable
	}
	contextID, planID, err := reviewPlanIDs(contextID, planID)
	if err != nil {
		return ApplyProgress{}, err
	}
	if len(snapshotHash) != 64 || !lowerHex(snapshotHash) ||
		len(reviewHash) != 64 || !lowerHex(reviewHash) {
		return ApplyProgress{}, ErrInvalidReview
	}
	progress := ApplyProgress{ReviewHash: reviewHash}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.state != "preview" && meta.state != "applying" && meta.state != "applied" ||
			meta.snapshotHash != snapshotHash {
			return ErrPlanUnavailable
		}
		var sourceID, frozenHash string
		if err := sc.Q.QueryRow(ctx, `SELECT source_id::text,review_hash
			FROM nms_import_plans WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, planID).Scan(&sourceID, &frozenHash); err != nil {
			return err
		}
		if frozenHash != reviewHash {
			return ErrPlanUnavailable
		}
		progress.RowCount, progress.State = meta.rowCount, meta.state
		var actualRows int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`, sc.Tenant.String(),
			contextID, planID).Scan(&actualRows); err != nil {
			return err
		}
		if actualRows != meta.rowCount {
			return ErrReviewStale
		}
		if meta.state == "applied" {
			return nil
		}
		if meta.configVersion != 0 {
			var proofCurrent bool
			if err := sc.Q.QueryRow(ctx, `SELECT coalesce(
				apply_verified_review_hash=$4 AND
				apply_verified_at>clock_timestamp()-interval '60 seconds',false)
				FROM nms_import_plans WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
				sc.Tenant.String(), contextID, planID, reviewHash).Scan(&proofCurrent); err != nil {
				return err
			}
			if !proofCurrent {
				return ErrReviewStale
			}
		}
		rows, err := sc.Q.Query(ctx, `SELECT row_number,object_kind,external_id,
			coalesce(label,''),coalesce(hostname,''),coalesce(address,''),action,
			coalesce(target_entity_id::text,''),coalesce(target_fingerprint,''),
			coalesce(target_group_revision,-1),
			unmapped_codes,reviewed_at IS NOT NULL
			FROM nms_import_rows WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			  AND state='pending' ORDER BY row_number LIMIT 100 FOR UPDATE`,
			sc.Tenant.String(), contextID, planID)
		if err != nil {
			return err
		}
		batch := make([]applyRow, 0, 100)
		for rows.Next() {
			var row applyRow
			if err := rows.Scan(&row.number, &row.kind, &row.externalID,
				&row.label, &row.hostname, &row.address, &row.action,
				&row.targetID, &row.fingerprint, &row.groupRevision, &row.unmapped,
				&row.reviewed); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, row := range batch {
			applied, err := applyFrozenRow(ctx, sc, contextID, planID, sourceID,
				meta.source == LibreNMS && meta.configVersion != 0, row)
			if err != nil {
				return err
			}
			if applied {
				progress.Applied++
			} else {
				progress.Skipped++
			}
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND state='pending'`,
			sc.Tenant.String(), contextID, planID).Scan(&progress.Remaining); err != nil {
			return err
		}
		progress.State = "applying"
		if progress.Remaining == 0 {
			progress.State = "applied"
		}
		// A live plan must re-read every source endpoint before its next
		// bounded chunk. The old proof cannot authorize a later write.
		if meta.configVersion != 0 {
			if _, err := sc.Q.Exec(ctx, `UPDATE nms_import_capture_steps
				SET apply_verified_at=NULL
				WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
				sc.Tenant.String(), contextID, planID); err != nil {
				return err
			}
		}
		command, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET state=$4,
			apply_verified_review_hash=NULL,apply_verified_at=NULL
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3
			  AND state IN ('preview','applying')`, sc.Tenant.String(), contextID,
			planID, progress.State)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrReviewStale
		}
		return s.audit(ctx, sc, "nms_import.chunk_applied", planID,
			map[string]any{"context_id": contextID, "snapshot_hash": snapshotHash,
				"review_hash": reviewHash, "applied": progress.Applied,
				"skipped": progress.Skipped, "remaining": progress.Remaining,
				"state": progress.State})
	})
	if err != nil {
		return ApplyProgress{}, err
	}
	return progress, nil
}

func applyFrozenRow(ctx context.Context, sc tenancy.Scope, contextID, planID,
	sourceID string, liveRemovalAllowed bool, row applyRow) (bool, error) {
	if !row.reviewed || !validReviewChoiceForKind(row.kind, ReviewChoice{
		Action: row.action, TargetEntityID: row.targetID}) ||
		row.action == "remove" && !liveRemovalAllowed ||
		row.action == "unmapped" && len(row.unmapped) == 0 {
		return false, ErrReviewStale
	}
	state, applied := "skipped", false
	switch row.action {
	case "skip", "unmapped":
	case "create", "update", "remove":
		if !reviewRowCanWrite(row.kind, row.action, row.unmapped,
			row.label, row.hostname, row.address) {
			return false, ErrReviewStale
		}
		var err error
		switch row.kind {
		case "device", "site":
			err = applyEntityRow(ctx, sc, contextID, planID, sourceID, row)
		case "group":
			err = applyGroupRow(ctx, sc, contextID, planID, sourceID, row)
		case "membership":
			if row.action == "remove" {
				err = applyMemberRemovalRow(ctx, sc, contextID, planID, sourceID, row)
			} else {
				err = applyMembershipRow(ctx, sc, contextID, planID, sourceID, row)
			}
		default:
			return false, ErrReviewStale
		}
		if err != nil {
			return false, err
		}
		state, applied = "applied", true
	default:
		return false, ErrReviewStale
	}
	command, err := sc.Q.Exec(ctx, `UPDATE nms_import_rows
		SET state=$5,applied_at=CASE WHEN $6 THEN clock_timestamp() ELSE NULL END
		WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND row_number=$4
		  AND state='pending'`, sc.Tenant.String(), contextID, planID,
		row.number, state, applied)
	if err != nil {
		return false, err
	}
	if command.RowsAffected() != 1 {
		return false, ErrReviewStale
	}
	return applied, nil
}

func applyGroupRow(ctx context.Context, sc tenancy.Scope, contextID, planID,
	sourceID string, row applyRow) error {
	if row.targetID != "" {
		return ErrReviewStale
	}
	dynamic := hasCode(row.unmapped, "dynamic_predicate_unmapped")
	if row.action == "update" {
		group, err := readImportedGroupTarget(ctx, sc, contextID, sourceID, row.externalID)
		if errors.Is(err, ErrInvalidReview) {
			return ErrReviewStale
		}
		if err != nil {
			return err
		}
		if group.fingerprint != row.fingerprint {
			return ErrReviewStale
		}
		command, err := sc.Q.Exec(ctx, `UPDATE nms_import_groups SET
			label=$5,dynamic_predicate_unmapped=$6,plan_id=$7,applied_at=clock_timestamp()
			WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND external_id=$4`,
			sc.Tenant.String(), contextID, sourceID, row.externalID,
			row.label, dynamic, planID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrReviewStale
		}
		return advanceImportedGroupRevision(ctx, sc, contextID, sourceID, row.externalID, planID)
	}
	if row.action != "create" || row.fingerprint != "" {
		return ErrReviewStale
	}
	command, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_groups
		(tenant_id,context_id,source_id,external_id,label,plan_id,dynamic_predicate_unmapped)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
		sc.Tenant.String(), contextID, sourceID, row.externalID, row.label, planID, dynamic)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		// A new, explicitly reviewed plan may encounter the same source-keyed
		// group after an earlier import. It is inert only when every mapped
		// field still matches; changed groups need a separate refresh review.
		var existingLabel string
		var existingDynamic bool
		if err := sc.Q.QueryRow(ctx, `SELECT label,dynamic_predicate_unmapped
			FROM nms_import_groups WHERE tenant_id=$1 AND context_id=$2
			  AND source_id=$3 AND external_id=$4 FOR SHARE`, sc.Tenant.String(), contextID,
			sourceID, row.externalID).Scan(&existingLabel, &existingDynamic); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrReviewStale
			}
			return err
		}
		if existingLabel != row.label || existingDynamic != dynamic {
			return ErrReviewStale
		}
	}
	return nil
}

func applyMembershipRow(ctx context.Context, sc tenancy.Scope, contextID, planID,
	sourceID string, row applyRow) error {
	if row.action != "create" || row.targetID != "" || row.fingerprint != "" ||
		!safeMembershipID(row.externalID) {
		return ErrReviewStale
	}
	groupID, deviceID, _ := strings.Cut(row.externalID, ":")
	var groupExists, deviceExists bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nms_import_groups
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND external_id=$4),
		EXISTS(SELECT 1 FROM nms_import_provenance
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
		  AND object_kind='device' AND external_id=$5)`, sc.Tenant.String(),
		contextID, sourceID, groupID, deviceID).Scan(&groupExists, &deviceExists); err != nil {
		return err
	}
	if !groupExists || !deviceExists {
		return ErrReviewStale
	}
	command, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_group_members
		(tenant_id,context_id,source_id,group_external_id,member_external_id,
		 row_external_id,plan_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
		sc.Tenant.String(), contextID, sourceID, groupID, deviceID,
		row.externalID, planID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		// An exact source pair from an earlier reviewed import is a no-op.
		// No label, address or foreign source can make a different member
		// look equivalent to this compound key.
		var existingRow string
		if err := sc.Q.QueryRow(ctx, `SELECT row_external_id FROM nms_import_group_members
			WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
			  AND group_external_id=$4 AND member_external_id=$5 FOR SHARE`,
			sc.Tenant.String(), contextID, sourceID, groupID, deviceID).Scan(&existingRow); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrReviewStale
			}
			return err
		}
		if existingRow != row.externalID {
			return ErrReviewStale
		}
		return nil
	}
	return advanceImportedGroupRevision(ctx, sc, contextID, sourceID, groupID, planID)
}

// Only an actual source-keyed group or member write advances this revision.
// A no-op retry must not make a frozen removal appear stale.
func advanceImportedGroupRevision(ctx context.Context, sc tenancy.Scope,
	contextID, sourceID, groupID, planID string) error {
	command, err := sc.Q.Exec(ctx, `UPDATE nms_import_groups SET
		revision=revision+1,
		revision_plan_delta=CASE WHEN revision_plan_id=$5 THEN revision_plan_delta+1 ELSE 1 END,
		revision_plan_id=$5
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND external_id=$4
		  AND revision<$6 AND revision_plan_delta<$6`, sc.Tenant.String(),
		contextID, sourceID, groupID, planID, int64(math.MaxInt64))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrReviewStale
	}
	return nil
}

func applyEntityRow(ctx context.Context, sc tenancy.Scope, contextID, planID,
	sourceID string, row applyRow) error {
	label := proposedEntityLabel(row.label, row.hostname, row.address)
	if label == "" {
		return ErrReviewStale
	}
	var boundID string
	err := sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM nms_import_provenance
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
		  AND object_kind=$4 AND external_id=$5`, sc.Tenant.String(), contextID,
		sourceID, row.kind, row.externalID).Scan(&boundID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	entityID := row.targetID
	if row.action == "create" {
		if boundID != "" || row.fingerprint != "" {
			return ErrReviewStale
		}
		entityID, err = captureUUID()
		if err != nil {
			return err
		}
		_, err = sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,$4,$5)`,
			sc.Tenant.String(), contextID, entityID, row.kind, label)
		if err != nil {
			return err
		}
	} else {
		if boundID != "" && boundID != entityID || len(row.fingerprint) != 64 {
			return ErrReviewStale
		}
		current, err := fingerprintReviewTarget(ctx, sc, contextID, entityID, row.kind)
		if err != nil {
			if errors.Is(err, ErrInvalidReview) {
				return ErrReviewStale
			}
			return err
		}
		if current != row.fingerprint {
			return ErrReviewStale
		}
		command, err := sc.Q.Exec(ctx, `UPDATE entities SET label=$4,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND kind=$5`,
			sc.Tenant.String(), contextID, entityID, label, row.kind)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrReviewStale
		}
	}
	if boundID == "" {
		command, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_provenance
			(tenant_id,context_id,source_id,object_kind,external_id,entity_id,plan_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			sc.Tenant.String(), contextID, sourceID, row.kind, row.externalID,
			entityID, planID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrReviewStale
		}
	}
	return nil
}
