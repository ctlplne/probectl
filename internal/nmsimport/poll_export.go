// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// PollTargetPreview is a credential-free, exact current binding for one
// reviewed source item. The source's IP and display name are never used to
// choose this agent target; source_ref comes from the operator's device anchor.
type PollTargetPreview struct {
	TenantID      string `json:"tenant_id"`
	ContextID     string `json:"context_id"`
	SourceID      string `json:"source_id"`
	ItemID        string `json:"item_external_id"`
	HostID        string `json:"host_external_id"`
	EntityID      string `json:"entity_id"`
	AgentID       string `json:"agent_id"`
	TargetAddress string `json:"target_address"`
	PollSeconds   int64  `json:"poll_seconds"`
	PlanID        string `json:"plan_id"`
	Revision      int64  `json:"revision"`
}

// PreviewPollTarget requires explicit source item, agent and configured target
// identities. The caller must authorize the import and entity read permissions
// for contextID; the FORCE-RLS transaction then proves all relations through
// tenant/context compound keys. A missing or revoked sender fails closed.
func (s CaptureStore) PreviewPollTarget(ctx context.Context, contextID, sourceID,
	itemID, agentID, targetAddress string) (PollTargetPreview, error) {
	if s.pool == nil || itemID == "" || safeZabbixUUID(itemID) != itemID ||
		agentID == "" || safeLabel(agentID) != agentID ||
		targetAddress == "" || safeLabel(targetAddress) != targetAddress {
		return PollTargetPreview{}, ErrInvalidReview
	}
	contextUUID, contextErr := uuid.Parse(contextID)
	sourceUUID, sourceErr := uuid.Parse(sourceID)
	if contextErr != nil || sourceErr != nil || contextUUID == uuid.Nil ||
		sourceUUID == uuid.Nil {
		return PollTargetPreview{}, ErrInvalidReview
	}
	contextID, sourceID = contextUUID.String(), sourceUUID.String()
	preview := PollTargetPreview{ContextID: contextID, SourceID: sourceID,
		ItemID: itemID, AgentID: agentID, TargetAddress: targetAddress}
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		preview.TenantID = sc.Tenant.String()
		err := sc.Q.QueryRow(ctx, `SELECT p.host_external_id,v.entity_id::text,
			p.poll_seconds,p.plan_id::text,p.revision
			FROM nms_import_poll_proposals p
			JOIN nms_import_sources s ON
			  (s.tenant_id,s.context_id,s.id)=(p.tenant_id,p.context_id,p.source_id)
			JOIN nms_import_provenance v ON
			  (v.tenant_id,v.context_id,v.source_id,v.object_kind,v.external_id)=
			  (p.tenant_id,p.context_id,p.source_id,p.host_kind,p.host_external_id)
			JOIN entities e ON
			  (e.tenant_id,e.context_id,e.id)=(v.tenant_id,v.context_id,v.entity_id)
			JOIN nms_import_plans plan ON
			  (plan.tenant_id,plan.context_id,plan.id,plan.source_id)=
			  (p.tenant_id,p.context_id,p.plan_id,p.source_id)
			JOIN nms_import_rows row ON
			  (row.tenant_id,row.context_id,row.plan_id,row.object_kind,row.external_id)=
			  (p.tenant_id,p.context_id,p.plan_id,p.object_kind,p.item_external_id)
			JOIN entity_source_contexts m ON
			  (m.tenant_id,m.context_id,m.anchor_entity_id)=
			  (e.tenant_id,e.context_id,e.id)
			JOIN entity_agent_contexts a ON
			  (a.tenant_id,a.context_id,a.agent_id)=
			  (m.tenant_id,m.context_id,m.agent_id)
			WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.source_id=$3
			  AND p.item_external_id=$4 AND s.source_kind='zabbix'
			  AND e.kind='device' AND plan.state='applied' AND row.state='applied'
			  AND m.source_kind='device_target' AND m.agent_id=$5 AND m.source_ref=$6
			  AND m.assigned_at<=statement_timestamp()
			  AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
			  AND a.assigned_at<=statement_timestamp()
			  AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
			  AND EXISTS (SELECT 1 FROM agent_identities i
			    WHERE i.tenant_id=p.tenant_id AND i.agent_id=m.agent_id
			      AND i.spiffe_id='spiffe://probectl/tenant/' || p.tenant_id::text ||
			        '/entity/' || m.agent_id
			      AND i.revoked_at IS NULL AND i.not_after>statement_timestamp())`,
			sc.Tenant.String(), contextID, sourceID, itemID, agentID,
			targetAddress).Scan(&preview.HostID, &preview.EntityID,
			&preview.PollSeconds, &preview.PlanID, &preview.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		return err
	})
	if err != nil {
		return PollTargetPreview{}, err
	}
	return preview, nil
}
