// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// PollProposal is an inert, credential-free applied source item. A current
// operator-owned agent target must still be verified separately before export.
type PollProposal struct {
	ItemID      string    `json:"item_external_id"`
	HostID      string    `json:"host_external_id"`
	PollSeconds int64     `json:"poll_seconds"`
	PlanID      string    `json:"plan_id"`
	Revision    int64     `json:"revision"`
	AppliedAt   time.Time `json:"applied_at"`
}

type PollProposalsPage struct {
	ContextID  string         `json:"context_id"`
	SourceID   string         `json:"source_id"`
	Items      []PollProposal `json:"items"`
	NextCursor *string        `json:"next_cursor,omitempty"`
}

// ListPollProposals uses a source/item keyset inside one FORCE-RLS tenant
// transaction. It is a live read, so the exact preview and revision must be
// checked again before exporting a device-agent configuration.
func (s CaptureStore) ListPollProposals(ctx context.Context, contextID,
	sourceID, after string, limit int) (PollProposalsPage, error) {
	if s.pool == nil || limit < 1 || limit > 100 ||
		(after != "" && safeZabbixUUID(after) != after) {
		return PollProposalsPage{}, ErrInvalidPage
	}
	contextUUID, contextErr := uuid.Parse(contextID)
	sourceUUID, sourceErr := uuid.Parse(sourceID)
	if contextErr != nil || sourceErr != nil || contextUUID == uuid.Nil ||
		sourceUUID == uuid.Nil {
		return PollProposalsPage{}, ErrPlanUnavailable
	}
	contextID, sourceID = contextUUID.String(), sourceUUID.String()
	page := PollProposalsPage{ContextID: contextID, SourceID: sourceID,
		Items: []PollProposal{}}
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var sourceKind string
		err := sc.Q.QueryRow(ctx, `SELECT source_kind FROM nms_import_sources
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3 FOR SHARE`,
			sc.Tenant.String(), contextID, sourceID).Scan(&sourceKind)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		if err != nil {
			return err
		}
		if sourceKind != "zabbix" {
			return ErrPlanUnavailable
		}
		rows, err := sc.Q.Query(ctx, `SELECT p.item_external_id,p.host_external_id,
			p.poll_seconds,p.plan_id::text,p.revision,p.applied_at
			FROM nms_import_poll_proposals p
			JOIN nms_import_plans plan ON
			  (plan.tenant_id,plan.context_id,plan.id,plan.source_id)=
			  (p.tenant_id,p.context_id,p.plan_id,p.source_id)
			JOIN nms_import_rows r ON
			  (r.tenant_id,r.context_id,r.plan_id,r.object_kind,r.external_id)=
			  (p.tenant_id,p.context_id,p.plan_id,p.object_kind,p.item_external_id)
			WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.source_id=$3
			  AND p.item_external_id>$4 AND plan.state='applied' AND r.state='applied'
			ORDER BY p.item_external_id LIMIT $5`, sc.Tenant.String(), contextID,
			sourceID, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item PollProposal
			if err := rows.Scan(&item.ItemID, &item.HostID, &item.PollSeconds,
				&item.PlanID, &item.Revision, &item.AppliedAt); err != nil {
				return err
			}
			if len(page.Items) == limit {
				cursor := page.Items[len(page.Items)-1].ItemID
				page.NextCursor = &cursor
				break
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return PollProposalsPage{}, err
	}
	return page, nil
}
