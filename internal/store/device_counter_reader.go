// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type DeviceCounterInterface struct {
	Scope       entity.Scope
	InterfaceID string
	IfIndex     uint32
	CreatedAt   time.Time
	ValidUntil  time.Time
	Source      flowstore.CounterSource
	Generation  int64
}

// CurrentInterfaceInScope selects a canonical interface and its exact current
// agent/source assignments under application-role RLS. It confers no actor
// grant; the caller authorizes the context in this same snapshot first.
// A device/index with competing current canonical owners is unavailable;
// expired or revoked sources cannot manufacture either ownership or ambiguity.
func (s *DeviceCounterCaptures) CurrentInterfaceInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, id string) (DeviceCounterInterface, error) {
	none := DeviceCounterInterface{}
	want, err := scope.Normalize()
	tenant, bound := tenancy.FromContext(ctx)
	if err != nil || !bound || tenant != sc.Tenant || tenant.String() != want.TenantID || sc.Q == nil {
		return none, entity.ErrScopeMismatch
	}
	id, err = validRegistryUUID(id)
	if err != nil {
		return none, err
	}
	out := DeviceCounterInterface{Scope: want, InterfaceID: id}
	err = sc.Q.QueryRow(ctx, `WITH current_interfaces AS (
        SELECT node.id,node.created_at,node.interface_index,parent.id AS device_id,source.agent_id,source.source_ref,
        source.assigned_at AS source_at,assignment.assigned_at AS agent_at,epoch.generation,
        LEAST(COALESCE(source.expires_at,certificate.valid_until),COALESCE(assignment.expires_at,certificate.valid_until),certificate.valid_until) AS valid_until,
        count(*) OVER (PARTITION BY node.parent_entity_id,node.interface_index) AS owners
        FROM entities node
        JOIN entities parent ON (parent.tenant_id,parent.context_id,parent.id,parent.kind)=
          (node.tenant_id,node.context_id,node.parent_entity_id,'device')
        JOIN entity_source_contexts source ON
          (source.tenant_id,source.context_id,source.agent_id,source.source_kind,source.source_ref,source.anchor_entity_id)=
          (node.tenant_id,node.context_id,node.source_agent_id,'device_target',node.configured_ref,parent.id)
        JOIN entity_agent_contexts assignment ON
          (assignment.tenant_id,assignment.agent_id,assignment.context_id)=(source.tenant_id,source.agent_id,source.context_id)
        JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=node.tenant_id AND NOT epoch.invalidating AND epoch.generation>0
        JOIN LATERAL (SELECT max(live.not_after) AS valid_until FROM agent_identities live
          WHERE live.tenant_id=source.tenant_id AND live.agent_id=source.agent_id
            AND live.spiffe_id='spiffe://probectl/tenant/' || source.tenant_id::text || '/entity/' || source.agent_id
            AND live.revoked_at IS NULL AND live.issued_at<=statement_timestamp() AND live.not_after>statement_timestamp()) certificate
          ON certificate.valid_until IS NOT NULL
        WHERE node.tenant_id=$1 AND node.context_id=$2 AND node.kind='interface' AND node.interface_index>0
          AND node.parent_entity_id=(SELECT focus.parent_entity_id FROM entities focus
            WHERE focus.tenant_id=$1 AND focus.context_id=$2 AND focus.id=$3 AND focus.kind='interface')
          AND source.assigned_at<=statement_timestamp() AND assignment.assigned_at<=statement_timestamp()
          AND (source.expires_at IS NULL OR source.expires_at>statement_timestamp())
          AND (assignment.expires_at IS NULL OR assignment.expires_at>statement_timestamp())
          AND NOT EXISTS (SELECT 1 FROM agent_identities revoked WHERE revoked.tenant_id=source.tenant_id AND revoked.agent_id=source.agent_id
            AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete'))
        SELECT interface_index,device_id::text,agent_id,source_ref,source_at,agent_at,generation,created_at,valid_until
        FROM current_interfaces WHERE id=$3 AND owners=1`,
		want.TenantID, want.ContextID, id).Scan(&out.IfIndex, &out.Source.DeviceID, &out.Source.AgentID, &out.Source.SourceRef,
		&out.Source.SourceAssignedAt, &out.Source.AgentAssignedAt, &out.Generation, &out.CreatedAt, &out.ValidUntil)
	if err != nil {
		return none, err
	}
	out.Source.ContextID = want.ContextID
	return out, ctx.Err()
}
