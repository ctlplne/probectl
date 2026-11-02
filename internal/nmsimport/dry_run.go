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

var ErrReviewStale = errors.New("nmsimport: reviewed destination changed")

// ReviewDiffItem states exactly what the present device/site mapper would
// write. Source addresses, group names and alert expressions never select a
// destination. A blank current label means there is no selected target.
type ReviewDiffItem struct {
	RowNumber     int64    `json:"row_number"`
	Kind          string   `json:"object_kind"`
	ExternalID    string   `json:"external_id"`
	Action        string   `json:"action"`
	TargetID      string   `json:"target_entity_id,omitempty"`
	CurrentLabel  string   `json:"current_label,omitempty"`
	ProposedLabel string   `json:"proposed_label,omitempty"`
	ChangedFields []string `json:"changed_fields"`
	UnmappedCodes []string `json:"unmapped_codes"`
}

type ReviewDiffPage struct {
	ContextID    string           `json:"context_id"`
	PlanID       string           `json:"plan_id"`
	SnapshotHash string           `json:"snapshot_hash"`
	ReviewHash   string           `json:"review_hash"`
	RowCount     int64            `json:"row_count"`
	Items        []ReviewDiffItem `json:"items"`
	NextCursor   *int64           `json:"next_cursor,omitempty"`
}

type reviewDiffRow struct {
	item        ReviewDiffItem
	label       string
	hostname    string
	address     string
	fingerprint string
	reviewed    bool
}

// ListReviewDiff is a bounded, read-only comparison of pending frozen choices. The
// caller must authorize nms.import.read in the selected context. A changed
// exact target refuses the whole page rather than displaying a stale merge.
func (s CaptureStore) ListReviewDiff(ctx context.Context, contextID, planID,
	reviewHash string, after int64, limit int) (ReviewDiffPage, error) {
	if s.pool == nil || limit < 1 || limit > 100 || after < -1 ||
		after == math.MaxInt64 || len(reviewHash) != 64 || !lowerHex(reviewHash) {
		return ReviewDiffPage{}, ErrInvalidPage
	}
	contextID, planID, err := reviewPlanIDs(contextID, planID)
	if err != nil {
		return ReviewDiffPage{}, err
	}
	page := ReviewDiffPage{ContextID: contextID, PlanID: planID,
		ReviewHash: reviewHash, Items: []ReviewDiffItem{}}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.state != "preview" && meta.state != "applying" {
			return ErrPlanUnavailable
		}
		var frozenHash, sourceID string
		if err := sc.Q.QueryRow(ctx, `SELECT review_hash,source_id::text FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, sc.Tenant.String(),
			contextID, planID).Scan(&frozenHash, &sourceID); err != nil {
			return err
		}
		if frozenHash != reviewHash {
			return ErrPlanUnavailable
		}
		page.SnapshotHash, page.RowCount = meta.snapshotHash, meta.rowCount
		// A deleted exact target cascades its reviewed row. Detect the missing
		// row even when it would fall on a different requested page.
		var currentCount int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`, sc.Tenant.String(),
			contextID, planID).Scan(&currentCount); err != nil {
			return err
		}
		if currentCount != meta.rowCount {
			return ErrReviewStale
		}
		rows, err := sc.Q.Query(ctx, `SELECT row_number,object_kind,external_id,
			coalesce(label,''),coalesce(hostname,''),coalesce(address,''),action,
			coalesce(target_entity_id::text,''),coalesce(target_fingerprint,''),
			unmapped_codes,reviewed_at IS NOT NULL
			FROM nms_import_rows WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
			AND row_number>$4 AND ($6='preview' OR state='pending')
			ORDER BY row_number LIMIT $5`, sc.Tenant.String(),
			contextID, planID, after, limit+1, meta.state)
		if err != nil {
			return err
		}
		candidate := make([]reviewDiffRow, 0, limit+1)
		for rows.Next() {
			var row reviewDiffRow
			if err := rows.Scan(&row.item.RowNumber, &row.item.Kind,
				&row.item.ExternalID, &row.label, &row.hostname, &row.address,
				&row.item.Action, &row.item.TargetID, &row.fingerprint,
				&row.item.UnmappedCodes, &row.reviewed); err != nil {
				rows.Close()
				return err
			}
			candidate = append(candidate, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(candidate) > limit {
			candidate = candidate[:limit]
			cursor := candidate[limit-1].item.RowNumber
			page.NextCursor = &cursor
		}
		for _, row := range candidate {
			item := row.item
			item.ChangedFields = []string{}
			if !row.reviewed || !validReviewChoice(ReviewChoice{
				Action: item.Action, TargetEntityID: item.TargetID}) {
				return ErrReviewStale
			}
			switch item.Action {
			case "create", "update":
				if !reviewRowCanWrite(item.Kind, item.Action, item.UnmappedCodes,
					row.label, row.hostname, row.address) {
					return ErrReviewStale
				}
				if item.Kind == "group" {
					item, err = reviewGroupDiff(ctx, sc, contextID, sourceID, row)
					if err != nil {
						return err
					}
					page.Items = append(page.Items, item)
					continue
				}
				if item.Kind == "membership" {
					item, err = reviewMembershipDiff(ctx, sc, contextID, sourceID, row)
					if err != nil {
						return err
					}
					page.Items = append(page.Items, item)
					continue
				}
				item.ProposedLabel = proposedEntityLabel(row.label, row.hostname,
					row.address)
				if item.ProposedLabel == "" {
					return ErrReviewStale
				}
				if item.Action == "update" {
					fingerprint, err := fingerprintReviewTarget(ctx, sc, contextID,
						item.TargetID, item.Kind)
					if err != nil {
						if errors.Is(err, ErrInvalidReview) {
							return ErrReviewStale
						}
						return err
					}
					if fingerprint != row.fingerprint {
						return ErrReviewStale
					}
					if err := sc.Q.QueryRow(ctx, `SELECT label FROM entities
						WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, sc.Tenant.String(),
						contextID, item.TargetID).Scan(&item.CurrentLabel); err != nil {
						if errors.Is(err, pgx.ErrNoRows) {
							return ErrReviewStale
						}
						return err
					}
				}
				if item.Action == "create" || item.CurrentLabel != item.ProposedLabel {
					item.ChangedFields = []string{"label"}
				}
			case "skip", "unmapped":
				// The source row remains visible through the sealed-row route.
				if item.Action == "unmapped" && len(item.UnmappedCodes) == 0 {
					return ErrReviewStale
				}
			default:
				return ErrReviewStale
			}
			page.Items = append(page.Items, item)
		}
		return nil
	})
	if err != nil {
		return ReviewDiffPage{}, err
	}
	return page, nil
}

func reviewGroupDiff(ctx context.Context, sc tenancy.Scope, contextID, sourceID string,
	row reviewDiffRow) (ReviewDiffItem, error) {
	item := row.item
	item.ProposedLabel = row.label
	item.ChangedFields = []string{}
	var oldLabel string
	var oldDynamic bool
	err := sc.Q.QueryRow(ctx, `SELECT label,dynamic_predicate_unmapped
		FROM nms_import_groups WHERE tenant_id=$1 AND context_id=$2
		  AND source_id=$3 AND external_id=$4`, sc.Tenant.String(),
		contextID, sourceID, item.ExternalID).Scan(&oldLabel, &oldDynamic)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ReviewDiffItem{}, err
	}
	if err == nil {
		if oldLabel != row.label || oldDynamic != hasCode(item.UnmappedCodes, "dynamic_predicate_unmapped") {
			return ReviewDiffItem{}, ErrReviewStale
		}
		item.CurrentLabel = oldLabel
	} else {
		item.ChangedFields = []string{"group"}
	}
	return item, nil
}

func reviewMembershipDiff(ctx context.Context, sc tenancy.Scope, contextID, sourceID string,
	row reviewDiffRow) (ReviewDiffItem, error) {
	item := row.item
	item.ChangedFields = []string{}
	groupID, deviceID, ok := strings.Cut(item.ExternalID, ":")
	if !ok || !safeMembershipID(item.ExternalID) {
		return ReviewDiffItem{}, ErrReviewStale
	}
	var oldRow string
	err := sc.Q.QueryRow(ctx, `SELECT row_external_id FROM nms_import_group_members
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
		  AND group_external_id=$4 AND member_external_id=$5`,
		sc.Tenant.String(), contextID, sourceID, groupID, deviceID).Scan(&oldRow)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ReviewDiffItem{}, err
	}
	if err == nil {
		if oldRow != item.ExternalID {
			return ReviewDiffItem{}, ErrReviewStale
		}
	} else {
		item.ChangedFields = []string{"membership"}
	}
	return item, nil
}

func proposedEntityLabel(label, hostname, address string) string {
	if label != "" {
		return label
	}
	if hostname != "" {
		return hostname
	}
	return address
}
