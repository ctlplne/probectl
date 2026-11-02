// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"math"
	"strings"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// appendLiveMemberRemovalCandidates is called only after every configured
// LibreNMS membership endpoint has been replay-verified. A file export and a
// partial live capture never reach this path. Candidates remain inert until
// an operator explicitly reviews each removal.
func (s CaptureStore) appendLiveMemberRemovalCandidates(ctx context.Context,
	contextID, planID string, step LiveCaptureStep) (int64, int64, error) {
	var tenantID, sourceID string
	var meta captureMeta
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantID = sc.Tenant.String()
		var readErr error
		meta, readErr = loadCaptureMeta(ctx, sc, contextID, planID, false)
		if readErr != nil {
			return readErr
		}
		if meta.source != LibreNMS || meta.configVersion == 0 || meta.state != "capturing" {
			return ErrPlanUnavailable
		}
		return sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			tenantID, contextID, planID).Scan(&sourceID)
	})
	if err != nil {
		return 0, 0, err
	}
	page, row := step.StartPage, step.StartRow
	lastGroup, lastMember := "", ""
	for {
		candidates, err := s.nextLiveMemberRemovals(ctx, contextID, planID,
			sourceID, lastGroup, lastMember)
		if err != nil {
			return 0, 0, err
		}
		if len(candidates) == 0 {
			break
		}
		if page == math.MaxInt64 || row > math.MaxInt64-int64(len(candidates)) {
			return 0, 0, ErrInvalidPage
		}
		snapshot := Snapshot{Source: LibreNMS, Rows: candidates}
		if _, err := s.appendSnapshot(ctx, contextID, planID, page,
			"member_removals", row, tenantID, meta, snapshot, step.leaseHash()); err != nil {
			return 0, 0, err
		}
		lastGroup, lastMember, _ = strings.Cut(candidates[len(candidates)-1].ExternalID, ":")
		page++
		row += int64(len(candidates))
	}
	return page, row, nil
}

func (s CaptureStore) nextLiveMemberRemovals(ctx context.Context, contextID,
	planID, sourceID, afterGroup, afterMember string) ([]Row, error) {
	out := make([]Row, 0, maxCaptureRowsPerPage)
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT gm.row_external_id
			FROM nms_import_group_members gm
			WHERE gm.tenant_id=$1 AND gm.context_id=$2 AND gm.source_id=$3
			  AND (gm.group_external_id,gm.member_external_id)>($5::text,$6::text)
			  AND EXISTS (SELECT 1 FROM nms_import_rows g
			    WHERE g.tenant_id=$1 AND g.context_id=$2 AND g.plan_id=$4
			      AND g.object_kind='group' AND g.external_id=gm.group_external_id)
			  AND NOT EXISTS (SELECT 1 FROM nms_import_rows m
			    WHERE m.tenant_id=$1 AND m.context_id=$2 AND m.plan_id=$4
			      AND m.object_kind='membership' AND m.external_id=gm.row_external_id
			      AND m.unmapped_codes @> ARRAY['group_unmapped']::text[])
			ORDER BY gm.group_external_id,gm.member_external_id LIMIT $7`,
			sc.Tenant.String(), contextID, sourceID, planID, afterGroup, afterMember,
			maxCaptureRowsPerPage)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			if !safeMembershipID(id) {
				return ErrInvalidPage
			}
			out = append(out, Row{Kind: "membership", ExternalID: id,
				UnmappedCodes: []string{"member_removal_candidate"}})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
