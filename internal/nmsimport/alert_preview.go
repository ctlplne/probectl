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

// LibreNMSAlertTargetPreview is one inert, finite port-down proposal. It
// carries no source expression, SQL, delivery operation, credential or
// notification channel. A preview grants no authority to enable an alert.
type LibreNMSAlertTargetPreview struct {
	TenantID      string `json:"tenant_id"`
	ContextID     string `json:"context_id"`
	SourceID      string `json:"source_id"`
	RuleID        string `json:"rule_external_id"`
	DeviceID      string `json:"device_external_id"`
	EntityID      string `json:"entity_id"`
	AgentID       string `json:"agent_id"`
	TargetAddress string `json:"target_address"`
	PlanID        string `json:"plan_id"`
	SnapshotHash  string `json:"snapshot_hash"`
	Name          string `json:"name"`
	Severity      string `json:"severity"`
	RuleKind      string `json:"rule_kind"`
	Enabled       bool   `json:"enabled"`
}

// PreviewLibreNMSAlertTarget requires the operator's exact source rule,
// agent and configured target. A normalized source selector can nominate a
// device, but only applied same-source provenance and live operator-owned
// sender/target bindings select the canonical destination. Every join is
// tenant/context qualified inside a FORCE-RLS transaction
// (docs/guardrails.md G7-1, G7-4).
func (s CaptureStore) PreviewLibreNMSAlertTarget(ctx context.Context,
	contextID, sourceID, ruleID, agentID, targetAddress string) (LibreNMSAlertTargetPreview, error) {
	if s.pool == nil || !canonicalSourceNumber(ruleID) ||
		agentID == "" || len(agentID) > 128 || safeLabel(agentID) != agentID ||
		targetAddress == "" || safeLabel(targetAddress) != targetAddress {
		return LibreNMSAlertTargetPreview{}, ErrInvalidReview
	}
	contextUUID, contextErr := uuid.Parse(contextID)
	sourceUUID, sourceErr := uuid.Parse(sourceID)
	if contextErr != nil || sourceErr != nil || contextUUID == uuid.Nil || sourceUUID == uuid.Nil {
		return LibreNMSAlertTargetPreview{}, ErrInvalidReview
	}
	contextID, sourceID = contextUUID.String(), sourceUUID.String()
	preview := LibreNMSAlertTargetPreview{
		ContextID: contextID, SourceID: sourceID, RuleID: ruleID,
		AgentID: agentID, TargetAddress: targetAddress,
		RuleKind: "port_down", Enabled: false,
	}
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return loadLibreNMSAlertTarget(ctx, sc, &preview, false)
	})
	if err != nil {
		return LibreNMSAlertTargetPreview{}, err
	}
	return preview, nil
}

// A write requests row locks so source provenance, the canonical entity and
// operator-owned sender assignment cannot change before its disabled native
// rule and import binding commit. The caller must still authorize the context.
func loadLibreNMSAlertTarget(ctx context.Context, sc tenancy.Scope,
	preview *LibreNMSAlertTargetPreview, lock bool) error {
	preview.TenantID = sc.Tenant.String()
	query := `SELECT r.parent_external_id,v.entity_id::text,
			p.id::text,p.snapshot_hash,r.label,r.severity
			FROM nms_import_rows r
			JOIN nms_import_plans p ON
			  (p.tenant_id,p.context_id,p.id)=(r.tenant_id,r.context_id,r.plan_id)
			JOIN nms_import_sources s ON
			  (s.tenant_id,s.context_id,s.id)=(p.tenant_id,p.context_id,p.source_id)
			JOIN nms_import_provenance v ON
			  (v.tenant_id,v.context_id,v.source_id,v.object_kind,v.external_id)=
			  (r.tenant_id,r.context_id,p.source_id,'device',r.parent_external_id)
			JOIN entities e ON
			  (e.tenant_id,e.context_id,e.id)=(v.tenant_id,v.context_id,v.entity_id)
			JOIN entity_source_contexts m ON
			  (m.tenant_id,m.context_id,m.anchor_entity_id)=
			  (e.tenant_id,e.context_id,e.id)
			JOIN entity_agent_contexts a ON
			  (a.tenant_id,a.context_id,a.agent_id)=
			  (m.tenant_id,m.context_id,m.agent_id)
			JOIN agent_identities i ON
			  (i.tenant_id,i.agent_id)=(a.tenant_id,a.agent_id)
			WHERE r.tenant_id=$1 AND r.context_id=$2 AND p.source_id=$3
			  AND r.object_kind='alert_rule' AND r.external_id=$4
			  AND s.source_kind='librenms' AND p.state='applied'
			  AND p.expires_at>statement_timestamp()
			  AND p.source_config_version=s.config_version
			  AND (p.source_config_version=0 OR s.fetch_enabled)
			  AND r.action='unmapped' AND r.state='skipped'
			  AND r.reviewed_at IS NOT NULL
			  AND r.parent_external_id IS NOT NULL
			  AND r.label IS NOT NULL AND octet_length(r.label) BETWEEN 1 AND 200
			  AND r.severity IN ('warning','critical')
			  AND r.unmapped_codes @> ARRAY['expression_unmapped']::text[]
			  AND e.kind='device'
			  AND m.source_kind='device_target' AND m.agent_id=$5 AND m.source_ref=$6
			  AND m.assigned_at<=statement_timestamp()
			  AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
			  AND a.assigned_at<=statement_timestamp()
			  AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
			  AND i.spiffe_id='spiffe://probectl/tenant/' || r.tenant_id::text ||
			    '/entity/' || m.agent_id
			  AND i.revoked_at IS NULL AND i.not_after>statement_timestamp()`
	if lock {
		query += ` FOR SHARE OF r,p,s,v,e,m,a,i`
	}
	err := sc.Q.QueryRow(ctx, query, sc.Tenant.String(), preview.ContextID,
		preview.SourceID, preview.RuleID, preview.AgentID,
		preview.TargetAddress).Scan(&preview.DeviceID, &preview.EntityID,
		&preview.PlanID, &preview.SnapshotHash, &preview.Name, &preview.Severity)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPlanUnavailable
	}
	return err
}
