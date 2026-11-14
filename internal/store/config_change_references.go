// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// VerifyConfigChangeReferencesInScope verifies original metadata and the exact
// current source incarnation in one RLS snapshot. It fetches no config content
// and never treats a reference or operator association as a read grant.
func (ChangeEvents) VerifyConfigChangeReferencesInScope(ctx context.Context, sc tenancy.Scope, events []change.Event, memoryBytes int64) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || sc.Q == nil {
		return entity.ErrScopeMismatch
	}
	if len(events) == 0 {
		return ctx.Err()
	}
	if memoryBytes < 4096 || int64(len(events)) > memoryBytes/4096 {
		return ErrClientReportBudget
	}
	type original struct {
		change.ConfigReference
		ObservedAt time.Time `json:"observed_at"`
		ArchivedAt time.Time `json:"archived_at"`
		Device     string    `json:"device"`
	}
	refs := make([]original, 0, len(events))
	for _, event := range events {
		if event.TenantID != tenant.String() || event.Config == nil || event.Config.Binding == nil {
			return entity.ErrScopeMismatch
		}
		refs = append(refs, original{*event.Config, event.OccurredAt, event.ReceivedAt, event.Target})
	}
	body, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	if int64(len(body)) > memoryBytes/4 {
		return ErrClientReportBudget
	}
	var matched int
	err = sc.Q.QueryRow(ctx, `SELECT count(*) FROM jsonb_to_recordset($2::jsonb)
 AS x(current_id uuid,current_version integer,current_hash text,previous_id uuid,previous_version integer,previous_hash text,binding jsonb,observed_at timestamptz,archived_at timestamptz,device text)
 JOIN device_configs current ON current.tenant_id=$1 AND current.id=x.current_id AND current.version=x.current_version
  AND current.content_hash=x.current_hash AND current.previous_hash=x.previous_hash AND current.content<>'' AND current.drifted
  AND current.observed_at=x.observed_at AND current.archived_at=x.archived_at AND current.device=x.device
 JOIN device_configs previous ON previous.tenant_id=current.tenant_id AND previous.id=x.previous_id
  AND previous.version=x.previous_version AND previous.version=current.version-1 AND previous.content_hash=x.previous_hash AND previous.content<>''
  AND (previous.entity_context_id,previous.device_entity_id,previous.binding_agent_id,previous.binding_source_ref,previous.binding_source_assigned_at,previous.binding_agent_assigned_at)=
      (current.entity_context_id,current.device_entity_id,current.binding_agent_id,current.binding_source_ref,current.binding_source_assigned_at,current.binding_agent_assigned_at)
 JOIN entity_source_contexts source ON (source.tenant_id,source.context_id,source.anchor_entity_id,source.agent_id,source.source_kind,source.source_ref,source.assigned_at)=
      (current.tenant_id,current.entity_context_id,current.device_entity_id,current.binding_agent_id,'device_target',current.binding_source_ref,current.binding_source_assigned_at)
 JOIN entity_agent_contexts agent ON (agent.tenant_id,agent.context_id,agent.agent_id,agent.assigned_at)=
      (current.tenant_id,current.entity_context_id,current.binding_agent_id,current.binding_agent_assigned_at)
 JOIN entities device ON (device.tenant_id,device.context_id,device.id)=(current.tenant_id,current.entity_context_id,current.device_entity_id) AND device.kind='device'
 WHERE x.binding->>'kind'='operator_bound_archive'
 AND current.entity_context_id=(x.binding->>'context_id')::uuid AND current.device_entity_id=(x.binding->>'device_entity_id')::uuid
 AND current.binding_agent_id=x.binding->>'agent_id' AND current.binding_source_ref=x.binding->>'source_ref'
 AND current.binding_source_assigned_at=(x.binding->>'source_assigned_at')::timestamptz
 AND current.binding_agent_assigned_at=(x.binding->>'agent_assigned_at')::timestamptz AND current.bound_at=(x.binding->>'bound_at')::timestamptz
 AND source.assigned_at<=statement_timestamp() AND agent.assigned_at<=statement_timestamp()
 AND (source.expires_at IS NULL OR source.expires_at>statement_timestamp()) AND (agent.expires_at IS NULL OR agent.expires_at>statement_timestamp())`, tenant.String(), string(body)).Scan(&matched)
	if err != nil {
		return err
	}
	if matched != len(refs) {
		return entity.ErrInvalidClaim
	}
	return ctx.Err()
}
