// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrInvalidReview    = errors.New("nmsimport: invalid review choice")
	ErrReviewIncomplete = errors.New("nmsimport: review has unassigned rows")
)

// ReviewChoice is an operator decision about one row of a sealed, redacted
// snapshot. A source response never supplies it. An update names an exact
// tenant/context entity; an address or label alone is never an identity match.
type ReviewChoice struct {
	RowNumber      int64  `json:"row_number"`
	Action         string `json:"action"`
	TargetEntityID string `json:"target_entity_id,omitempty"`
}

// SetReviewChoices records up to 100 explicit choices in one tenant transaction.
// The caller must authorize nms.import.write for the selected routing context.
// Each destination reference is checked in that same FORCE-RLS transaction.
func (s CaptureStore) SetReviewChoices(ctx context.Context, contextID, planID,
	snapshotHash string, choices []ReviewChoice) error {
	if s.pool == nil || s.audit == nil {
		return ErrCaptureAuditUnavailable
	}
	contextID, planID, err := reviewPlanIDs(contextID, planID)
	if err != nil {
		return err
	}
	if len(snapshotHash) != 64 || !lowerHex(snapshotHash) ||
		len(choices) == 0 || len(choices) > 100 {
		return ErrInvalidReview
	}
	seen := make(map[int64]bool, len(choices))
	for _, choice := range choices {
		if choice.RowNumber < 0 || seen[choice.RowNumber] ||
			!validReviewChoice(choice) {
			return ErrInvalidReview
		}
		seen[choice.RowNumber] = true
	}
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.state != "sealed" || meta.snapshotHash != snapshotHash {
			return ErrPlanUnavailable
		}
		var sourceID string
		if err := sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, sc.Tenant.String(),
			contextID, planID).Scan(&sourceID); err != nil {
			return err
		}
		changed := 0
		for _, choice := range choices {
			updated, err := setOneReviewChoice(ctx, sc, contextID, planID, sourceID, choice)
			if err != nil {
				return err
			}
			if updated {
				changed++
			}
		}
		if changed == 0 {
			return nil
		}
		return s.audit(ctx, sc, "nms_import.review_choices_set", planID,
			map[string]any{"context_id": contextID, "snapshot_hash": snapshotHash,
				"changed_rows": changed})
	})
}

func validReviewChoice(choice ReviewChoice) bool {
	switch choice.Action {
	case "create", "skip", "unmapped":
		return choice.TargetEntityID == ""
	case "update":
		id, err := uuid.Parse(choice.TargetEntityID)
		return err == nil && id != uuid.Nil && id.String() == choice.TargetEntityID
	default:
		return false
	}
}

func setOneReviewChoice(ctx context.Context, sc tenancy.Scope, contextID, planID,
	sourceID string, choice ReviewChoice) (bool, error) {
	var kind, externalID, oldAction, oldTarget, oldFingerprint string
	var unmapped []string
	var reviewed bool
	err := sc.Q.QueryRow(ctx, `SELECT object_kind,external_id,unmapped_codes,action,
		coalesce(target_entity_id::text,''),coalesce(target_fingerprint,''),
		reviewed_at IS NOT NULL
		FROM nms_import_rows WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
		  AND row_number=$4 FOR UPDATE`, sc.Tenant.String(), contextID,
		planID, choice.RowNumber).
		Scan(&kind, &externalID, &unmapped, &oldAction, &oldTarget,
			&oldFingerprint, &reviewed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrInvalidReview
	}
	if err != nil {
		return false, err
	}
	if choice.Action == "unmapped" && len(unmapped) == 0 {
		return false, ErrInvalidReview
	}
	fingerprint := ""
	if choice.Action == "create" || choice.Action == "update" {
		if (kind != "device" && kind != "site") || len(unmapped) != 0 {
			return false, ErrInvalidReview
		}
		var bound string
		err := sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM nms_import_provenance
			WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
			  AND object_kind=$4 AND external_id=$5`, sc.Tenant.String(),
			contextID, sourceID, kind, externalID).Scan(&bound)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
		if choice.Action == "create" && bound != "" ||
			choice.Action == "update" && bound != "" && bound != choice.TargetEntityID {
			return false, ErrInvalidReview
		}
		if choice.Action == "update" {
			fingerprint, err = fingerprintReviewTarget(ctx, sc, contextID,
				choice.TargetEntityID, kind)
			if err != nil {
				return false, err
			}
		}
	}
	if reviewed && oldAction == choice.Action && oldTarget == choice.TargetEntityID {
		if oldFingerprint == fingerprint {
			return false, nil
		}
		if oldFingerprint != "" {
			return false, ErrInvalidReview
		}
	}
	var target any
	if choice.TargetEntityID != "" {
		target = choice.TargetEntityID
	}
	var targetFingerprint any
	if fingerprint != "" {
		targetFingerprint = fingerprint
	}
	command, err := sc.Q.Exec(ctx, `UPDATE nms_import_rows SET
		action=$5,target_entity_id=$6,target_fingerprint=$7,reviewed_at=clock_timestamp()
		WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND row_number=$4`,
		sc.Tenant.String(), contextID, planID, choice.RowNumber, choice.Action,
		target, targetFingerprint)
	if err != nil {
		return false, captureWriteErr(err)
	}
	if command.RowsAffected() != 1 {
		return false, ErrInvalidReview
	}
	return true, nil
}

// A source label or address never identifies a destination. This digest binds
// the operator's exact target to its current content and revision, so a later
// merge cannot overwrite a concurrently edited canonical entity.
func fingerprintReviewTarget(ctx context.Context, sc tenancy.Scope, contextID,
	entityID, expectedKind string) (string, error) {
	var kind, label, parent, agent, configured string
	var index int64
	var updated time.Time
	err := sc.Q.QueryRow(ctx, `SELECT kind,label,coalesce(parent_entity_id::text,''),
		coalesce(source_agent_id,''),coalesce(configured_ref,''),
		coalesce(interface_index,-1),updated_at FROM entities
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3 FOR SHARE`,
		sc.Tenant.String(), contextID, entityID).
		Scan(&kind, &label, &parent, &agent, &configured, &index, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidReview
	}
	if err != nil {
		return "", err
	}
	if kind != expectedKind {
		return "", ErrInvalidReview
	}
	fields := []string{"probectl:nms-target:v1", sc.Tenant.String(), contextID,
		entityID, kind, label, parent, agent, configured,
		strconv.FormatInt(index, 10), updated.UTC().Format(time.RFC3339Nano)}
	return hex.EncodeToString(crypto.Default.Hash([]byte(strings.Join(fields, "\x00")))), nil
}

// FinalizeReview freezes every explicit row decision into a tenant/context,
// source-version and snapshot-bound hash. It performs no destination write.
// A partial review cannot advance the plan to preview.
func (s CaptureStore) FinalizeReview(ctx context.Context, contextID, planID,
	snapshotHash string) (string, error) {
	if s.pool == nil || s.audit == nil {
		return "", ErrCaptureAuditUnavailable
	}
	contextID, planID, err := reviewPlanIDs(contextID, planID)
	if err != nil {
		return "", err
	}
	if len(snapshotHash) != 64 || !lowerHex(snapshotHash) {
		return "", ErrInvalidReview
	}
	var reviewHash string
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if (meta.state != "sealed" && meta.state != "preview") ||
			meta.snapshotHash != snapshotHash {
			return ErrPlanUnavailable
		}
		header := "probectl:nms-review:v2\x00" + sc.Tenant.String() + "\x00" +
			contextID + "\x00" + planID + "\x00" + snapshotHash + "\x00" +
			strconv.FormatInt(meta.configVersion, 10)
		sum := crypto.Default.Hash([]byte(header))
		rows, err := sc.Q.Query(ctx, `SELECT row_number,action,
			coalesce(target_entity_id::text,''),coalesce(target_fingerprint,''),
			reviewed_at IS NOT NULL
			FROM nms_import_rows WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			ORDER BY row_number`, sc.Tenant.String(), contextID, planID)
		if err != nil {
			return err
		}
		next := int64(0)
		for rows.Next() {
			var rowNumber int64
			var action, target, fingerprint string
			var reviewed bool
			if err := rows.Scan(&rowNumber, &action, &target, &fingerprint,
				&reviewed); err != nil {
				rows.Close()
				return err
			}
			if !reviewed || rowNumber != next ||
				!validReviewChoice(ReviewChoice{Action: action, TargetEntityID: target}) ||
				(action == "update" && (len(fingerprint) != 64 || !lowerHex(fingerprint))) ||
				(action != "update" && fingerprint != "") {
				rows.Close()
				return ErrReviewIncomplete
			}
			frame := append(append([]byte(nil), sum...), 0)
			frame = strconv.AppendInt(frame, rowNumber, 10)
			frame = append(frame, 0)
			frame = append(frame, action...)
			frame = append(frame, 0)
			frame = append(frame, target...)
			frame = append(frame, 0)
			frame = append(frame, fingerprint...)
			sum = crypto.Default.Hash(frame)
			next++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if next != meta.rowCount {
			return ErrReviewIncomplete
		}
		reviewHash = hex.EncodeToString(sum)
		if meta.state == "preview" {
			var stored string
			if err := sc.Q.QueryRow(ctx, `SELECT review_hash FROM nms_import_plans
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, sc.Tenant.String(),
				contextID, planID).Scan(&stored); err != nil {
				return err
			}
			if stored != reviewHash {
				return ErrPlanUnavailable
			}
			return nil
		}
		command, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET state='preview',review_hash=$4
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND state='sealed'`,
			sc.Tenant.String(), contextID, planID, reviewHash)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrPlanUnavailable
		}
		return s.audit(ctx, sc, "nms_import.review_finalized", planID,
			map[string]any{"context_id": contextID, "snapshot_hash": snapshotHash,
				"review_hash": reviewHash, "row_count": meta.rowCount})
	})
	if err != nil {
		return "", err
	}
	return reviewHash, nil
}

func reviewPlanIDs(contextID, planID string) (string, string, error) {
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil {
		return "", "", ErrPlanUnavailable
	}
	planUUID, err := uuid.Parse(planID)
	if err != nil || planUUID == uuid.Nil {
		return "", "", ErrPlanUnavailable
	}
	return contextUUID.String(), planUUID.String(), nil
}
