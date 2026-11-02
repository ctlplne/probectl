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
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type importedPollTarget struct {
	hostID      string
	seconds     int64
	revision    int64
	fingerprint string
}

// A poll choice needs the device row from this reviewed plan or an already
// applied binding from the same source. Neither its address nor host label can
// select a destination. This is checked after every row has a review choice.
func validatePollProposalChoices(ctx context.Context, sc tenancy.Scope,
	contextID, planID string) error {
	var sourceID string
	if err := sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, sc.Tenant.String(),
		contextID, planID).Scan(&sourceID); err != nil {
		return err
	}
	var unsupported int64
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows p
		WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.plan_id=$3
		  AND p.object_kind='poll_setting' AND p.action IN ('create','update')
		  AND NOT EXISTS (SELECT 1 FROM nms_import_rows d
		      WHERE d.tenant_id=p.tenant_id AND d.context_id=p.context_id
		        AND d.plan_id=p.plan_id AND d.object_kind='device'
		        AND d.external_id=p.parent_external_id
		        AND d.action IN ('create','update'))
		  AND NOT EXISTS (SELECT 1 FROM nms_import_provenance v
		      WHERE v.tenant_id=p.tenant_id AND v.context_id=p.context_id
		        AND v.source_id=$4 AND v.object_kind='device'
		        AND v.external_id=p.parent_external_id)`, sc.Tenant.String(),
		contextID, planID, sourceID).Scan(&unsupported); err != nil {
		return err
	}
	if unsupported != 0 {
		return ErrReviewIncomplete
	}
	var conflicting int64
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM (
		SELECT parent_external_id FROM nms_import_rows
		WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
		  AND object_kind='poll_setting' AND action IN ('create','update')
		GROUP BY parent_external_id HAVING count(DISTINCT poll_seconds)>1
	) AS hosts`, sc.Tenant.String(), contextID, planID).Scan(&conflicting); err != nil {
		return err
	}
	if conflicting != 0 {
		return ErrReviewIncomplete
	}
	return nil
}

func fingerprintPollChoice(ctx context.Context, sc tenancy.Scope, contextID,
	planID, sourceID string, sourceKind Kind, itemID, hostID string,
	seconds int64, action string) (string, error) {
	if sourceKind != Zabbix || itemID == "" || safeZabbixUUID(itemID) != itemID ||
		hostID == "" || safeLabel(hostID) != hostID ||
		seconds < 15 || seconds > 86400 {
		return "", ErrInvalidReview
	}
	var hostCaptured bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nms_import_rows
		WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
		  AND object_kind='device' AND external_id=$4)`,
		sc.Tenant.String(), contextID, planID, hostID).Scan(&hostCaptured); err != nil {
		return "", err
	}
	if !hostCaptured {
		return "", ErrInvalidReview
	}
	if action == "create" {
		return "", nil
	}
	if action != "update" {
		return "", ErrInvalidReview
	}
	target, err := readImportedPollTarget(ctx, sc, contextID, sourceID, itemID)
	if err != nil {
		return "", err
	}
	if target.hostID != hostID {
		return "", ErrInvalidReview
	}
	return target.fingerprint, nil
}

// An importer never identifies a device by its source address or label. The
// exact source item and its previously reviewed proposal form the update
// target; a concurrent plan changing either must invalidate the frozen hash.
func readImportedPollTarget(ctx context.Context, sc tenancy.Scope, contextID,
	sourceID, itemID string) (importedPollTarget, error) {
	var target importedPollTarget
	var planID string
	var appliedAt time.Time
	err := sc.Q.QueryRow(ctx, `SELECT host_external_id,poll_seconds,revision,
		plan_id::text,applied_at FROM nms_import_poll_proposals
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
		  AND item_external_id=$4 FOR SHARE`, sc.Tenant.String(), contextID,
		sourceID, itemID).Scan(&target.hostID, &target.seconds, &target.revision,
		&planID, &appliedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return importedPollTarget{}, ErrInvalidReview
	}
	if err != nil {
		return importedPollTarget{}, err
	}
	fields := []string{"probectl:nms-poll-target:v1", sc.Tenant.String(), contextID,
		sourceID, itemID, target.hostID, strconv.FormatInt(target.seconds, 10),
		planID, appliedAt.UTC().Format(time.RFC3339Nano),
		strconv.FormatInt(target.revision, 10)}
	target.fingerprint = hex.EncodeToString(crypto.Default.Hash([]byte(strings.Join(fields, "\x00"))))
	return target, nil
}

// The source lock held by ApplyReview serializes proposals from competing
// plans for one source. The foreign key still makes the provenance boundary
// authoritative if the host binding disappears before this insert or update.
func applyPollProposalRow(ctx context.Context, sc tenancy.Scope, contextID,
	planID, sourceID string, row applyRow) error {
	if row.targetID != "" || row.externalID == "" ||
		safeZabbixUUID(row.externalID) != row.externalID ||
		row.parentID == "" || safeLabel(row.parentID) != row.parentID ||
		row.pollSeconds < 15 || row.pollSeconds > 86400 {
		return ErrReviewStale
	}
	if row.action == "create" {
		if row.fingerprint != "" {
			return ErrReviewStale
		}
		command, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_poll_proposals
			(tenant_id,context_id,source_id,host_external_id,
			 item_external_id,poll_seconds,plan_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			sc.Tenant.String(), contextID, sourceID, row.parentID,
			row.externalID, row.pollSeconds, planID)
		if err != nil {
			return captureWriteErr(err)
		}
		if command.RowsAffected() == 1 {
			return nil
		}
		// Re-importing an identical source item is inert. A changed interval
		// must be reviewed separately as an update against its fingerprint.
		current, err := readImportedPollTarget(ctx, sc, contextID, sourceID,
			row.externalID)
		if err != nil {
			if errors.Is(err, ErrInvalidReview) {
				return ErrReviewStale
			}
			return err
		}
		if current.hostID != row.parentID || current.seconds != row.pollSeconds {
			return ErrReviewStale
		}
		return nil
	}
	if row.action != "update" || len(row.fingerprint) != 64 {
		return ErrReviewStale
	}
	current, err := readImportedPollTarget(ctx, sc, contextID, sourceID,
		row.externalID)
	if err != nil {
		if errors.Is(err, ErrInvalidReview) {
			return ErrReviewStale
		}
		return err
	}
	if current.hostID != row.parentID || current.fingerprint != row.fingerprint {
		return ErrReviewStale
	}
	if current.seconds == row.pollSeconds {
		return nil
	}
	command, err := sc.Q.Exec(ctx, `UPDATE nms_import_poll_proposals SET
		poll_seconds=$5,plan_id=$6,revision=revision+1,
		applied_at=clock_timestamp()
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
		  AND item_external_id=$4 AND revision=$7 AND revision<$8`,
		sc.Tenant.String(), contextID, sourceID, row.externalID,
		row.pollSeconds, planID, current.revision, int64(math.MaxInt64))
	if err != nil {
		return captureWriteErr(err)
	}
	if command.RowsAffected() != 1 {
		return ErrReviewStale
	}
	return nil
}
