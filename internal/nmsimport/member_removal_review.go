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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type importedMemberTarget struct {
	fingerprint   string
	groupRevision int64
}

// A choice made before another plan changed the group or member cannot be
// frozen. Read bounded batches so a large source is not held in Go memory.
func validateMemberRemovalChoices(ctx context.Context, sc tenancy.Scope,
	contextID, planID string) error {
	var sourceID string
	if err := sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
		sc.Tenant.String(), contextID, planID).Scan(&sourceID); err != nil {
		return err
	}
	var after int64 = -1
	for {
		batch, err := readMemberRemovalChoices(ctx, sc, contextID, planID, after)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			member, err := readImportedMemberTarget(ctx, sc, contextID, sourceID,
				row.externalID)
			if err != nil || member.fingerprint != row.fingerprint ||
				member.groupRevision != row.groupRevision {
				if err != nil && !errors.Is(err, ErrInvalidReview) {
					return err
				}
				return ErrReviewStale
			}
		}
		after = batch[len(batch)-1].number
	}
}

type memberRemovalChoice struct {
	number        int64
	externalID    string
	fingerprint   string
	groupRevision int64
}

func readMemberRemovalChoices(ctx context.Context, sc tenancy.Scope,
	contextID, planID string, after int64) ([]memberRemovalChoice, error) {
	rows, err := sc.Q.Query(ctx, `SELECT row_number,external_id,
		coalesce(target_fingerprint,''),coalesce(target_group_revision,-1)
		FROM nms_import_rows WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
		  AND row_number>$4 AND object_kind='membership' AND action='remove'
		ORDER BY row_number LIMIT 100`, sc.Tenant.String(), contextID, planID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]memberRemovalChoice, 0, 100)
	for rows.Next() {
		var item memberRemovalChoice
		if err := rows.Scan(&item.number, &item.externalID, &item.fingerprint,
			&item.groupRevision); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// A removal points only at the exact member of this tenant/context/source
// group. The fingerprint covers the old binding and its write revision.
func readImportedMemberTarget(ctx context.Context, sc tenancy.Scope, contextID,
	sourceID, externalID string) (importedMemberTarget, error) {
	if !safeMembershipID(externalID) {
		return importedMemberTarget{}, ErrInvalidReview
	}
	groupID, memberID, _ := strings.Cut(externalID, ":")
	group, err := readImportedGroupTarget(ctx, sc, contextID, sourceID, groupID)
	if err != nil {
		return importedMemberTarget{}, err
	}
	var oldRow, oldPlan string
	var appliedAt time.Time
	err = sc.Q.QueryRow(ctx, `SELECT row_external_id,plan_id::text,applied_at
		FROM nms_import_group_members WHERE tenant_id=$1 AND context_id=$2
		  AND source_id=$3 AND group_external_id=$4 AND member_external_id=$5
		FOR SHARE`, sc.Tenant.String(), contextID, sourceID, groupID, memberID).
		Scan(&oldRow, &oldPlan, &appliedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return importedMemberTarget{}, ErrInvalidReview
	}
	if err != nil {
		return importedMemberTarget{}, err
	}
	if oldRow != externalID {
		return importedMemberTarget{}, ErrInvalidReview
	}
	fields := []string{"probectl:nms-member-target:v1", sc.Tenant.String(),
		contextID, sourceID, groupID, memberID, oldPlan,
		appliedAt.UTC().Format(time.RFC3339Nano)}
	return importedMemberTarget{
		fingerprint:   hex.EncodeToString(crypto.Default.Hash([]byte(strings.Join(fields, "\x00")))),
		groupRevision: group.revision,
	}, nil
}

// A group's latest plan and its in-plan revision delta distinguish writes
// made by this reviewed plan from any concurrent plan. Every actual group
// label, membership-add or membership-remove write increments the revision.
func expectedMemberRemovalRevision(ctx context.Context, sc tenancy.Scope,
	contextID, sourceID, groupID, planID string, baseline int64) error {
	var current, ownDelta int64
	var lastPlan string
	err := sc.Q.QueryRow(ctx, `SELECT revision,coalesce(revision_plan_id::text,''),
		revision_plan_delta FROM nms_import_groups
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND external_id=$4
		FOR SHARE`, sc.Tenant.String(), contextID, sourceID, groupID).
		Scan(&current, &lastPlan, &ownDelta)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrReviewStale
	}
	if err != nil {
		return err
	}
	expected := baseline
	if lastPlan == planID {
		if ownDelta < 0 || baseline > math.MaxInt64-ownDelta {
			return ErrReviewStale
		}
		expected += ownDelta
	}
	if current != expected {
		return ErrReviewStale
	}
	return nil
}

func reviewMembershipRemovalDiff(ctx context.Context, sc tenancy.Scope,
	contextID, sourceID, planID string, row reviewDiffRow) (ReviewDiffItem, error) {
	item := row.item
	if item.Action != "remove" || item.TargetID != "" ||
		len(item.UnmappedCodes) != 1 ||
		item.UnmappedCodes[0] != "member_removal_candidate" ||
		row.groupRevision < 0 {
		return ReviewDiffItem{}, ErrReviewStale
	}
	member, err := readImportedMemberTarget(ctx, sc, contextID, sourceID,
		item.ExternalID)
	if errors.Is(err, ErrInvalidReview) {
		return ReviewDiffItem{}, ErrReviewStale
	}
	if err != nil {
		return ReviewDiffItem{}, err
	}
	if member.fingerprint != row.fingerprint {
		return ReviewDiffItem{}, ErrReviewStale
	}
	groupID, _, _ := strings.Cut(item.ExternalID, ":")
	if err := expectedMemberRemovalRevision(ctx, sc, contextID, sourceID,
		groupID, planID, row.groupRevision); err != nil {
		return ReviewDiffItem{}, err
	}
	item.ChangedFields = []string{"membership_removed"}
	return item, nil
}

// A removal writes only the previously imported exact member pair. The
// fingerprint and group revision were frozen in the operator's review hash.
func applyMemberRemovalRow(ctx context.Context, sc tenancy.Scope,
	contextID, planID, sourceID string, row applyRow) error {
	if row.action != "remove" || row.targetID != "" ||
		len(row.fingerprint) != 64 || !lowerHex(row.fingerprint) ||
		row.groupRevision < 0 || !safeMembershipID(row.externalID) ||
		len(row.unmapped) != 1 || row.unmapped[0] != "member_removal_candidate" {
		return ErrReviewStale
	}
	groupID, memberID, _ := strings.Cut(row.externalID, ":")
	member, err := readImportedMemberTarget(ctx, sc, contextID, sourceID, row.externalID)
	if errors.Is(err, ErrInvalidReview) {
		return ErrReviewStale
	}
	if err != nil {
		return err
	}
	if member.fingerprint != row.fingerprint {
		return ErrReviewStale
	}
	if err := expectedMemberRemovalRevision(ctx, sc, contextID, sourceID,
		groupID, planID, row.groupRevision); err != nil {
		return err
	}
	command, err := sc.Q.Exec(ctx, `DELETE FROM nms_import_group_members
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
		  AND group_external_id=$4 AND member_external_id=$5
		  AND row_external_id=$6`, sc.Tenant.String(), contextID, sourceID,
		groupID, memberID, row.externalID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrReviewStale
	}
	return advanceImportedGroupRevision(ctx, sc, contextID, sourceID, groupID, planID)
}
