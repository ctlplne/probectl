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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

// IncidentConfiguredTest is operator-owned current configuration, not a probe
// result or proof that an incident caused a failure. Only an explicit source
// anchor and matching current test/path contexts supply membership; matching
// addresses, incident prose and old observations cannot invent a test identity.
type IncidentConfiguredTest struct {
	TenantID                             string
	SourceGeneration                     int64
	ContextID, EntityID, TestID, AgentID string
	Name, Type, Target                   string
	CurrentSince                         time.Time
	ValidUntil                           *time.Time
	MeasurementIdentityUntil             *time.Time
	Definition                           testspec.ExecutableDefinition
}

// ConfiguredImpactTestsInScope reads the complete enabled, explicitly anchored
// population through the same tenant snapshot as canonical incident membership.
// Callers authorize tests before invoking this read and each returned resource
// before disclosure. A resource failure returns no usable population prefix.
func (Incidents) ConfiguredImpactTestsInScope(ctx context.Context, sc tenancy.Scope, inputs *IncidentImpactInputs, maxBytes int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity, string) error) ([]IncidentConfiguredTest, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || inputs == nil || inputs.TenantID != bound.String() || sc.Q == nil || authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	if inputs.SourceGeneration <= 0 || inputs.SourceGeneration != generation {
		return nil, sourceepoch.ErrInvalidating
	}
	if maxBytes < 4096 || int64(len(inputs.Entities)) > maxBytes/1024 {
		return nil, ErrIncidentImpactBudget
	}
	contexts, entities := make([]string, 0, len(inputs.Entities)), make([]string, 0, len(inputs.Entities))
	members := map[string]IncidentImpactEntity{}
	for _, member := range inputs.Entities {
		if _, err := validRegistryUUID(member.EntityID); err != nil {
			return nil, err
		}
		if _, err := validRegistryUUID(member.ContextID); err != nil {
			return nil, err
		}
		identity := member.ContextID + ":" + member.EntityID
		if _, seen := members[identity]; seen {
			continue
		}
		record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, member.ContextID)
		if err != nil {
			return nil, err
		}
		if err := authorize(ctx, record, member, ""); err != nil {
			return nil, err
		}
		members[identity] = member
		contexts, entities = append(contexts, member.ContextID), append(entities, member.EntityID)
	}
	return readIncidentConfiguredTests(ctx, sc, contexts, entities, members, inputs.SourceGeneration, maxBytes, authorize)
}

func readIncidentConfiguredTests(ctx context.Context, sc tenancy.Scope, contexts, entities []string, members map[string]IncidentImpactEntity, generation, maxBytes int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity, string) error) ([]IncidentConfiguredTest, error) {
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
  SELECT * FROM unnest($2::uuid[],$3::uuid[]) AS r(context_id,entity_id))
 SELECT m.context_id::text,m.anchor_entity_id::text,t.id::text,m.agent_id,t.type,
 CASE WHEN octet_length(t.name)+octet_length(t.target)+octet_length(COALESCE(p.path_target,''))+octet_length(t.params::text)<=$4 THEN t.name END,
 CASE WHEN octet_length(t.name)+octet_length(t.target)+octet_length(COALESCE(p.path_target,''))+octet_length(t.params::text)<=$4 THEN t.target END,
 CASE WHEN octet_length(t.name)+octet_length(t.target)+octet_length(COALESCE(p.path_target,''))+octet_length(t.params::text)<=$4 THEN COALESCE(p.path_target,'') END,
 GREATEST(node.created_at,m.assigned_at,a.assigned_at,c.assigned_at,CASE WHEN t.type='icmp' THEN p.assigned_at ELSE c.assigned_at END,t.updated_at,epoch.observation_not_before),
 LEAST(m.expires_at,a.expires_at),t.interval_seconds,t.timeout_seconds,
 CASE WHEN octet_length(t.params::text)<=$4 THEN t.params END,
 (SELECT max(identity.not_after) FROM agent_identities identity
 WHERE identity.tenant_id=$1 AND identity.agent_id=m.agent_id
 AND identity.spiffe_id='spiffe://probectl/tenant/'||$1::text||'/entity/'||m.agent_id
 AND identity.issued_at<=transaction_timestamp() AND identity.not_after>transaction_timestamp() AND identity.revoked_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM agent_identities revoked WHERE revoked.tenant_id=$1 AND revoked.agent_id=m.agent_id
 AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete'))
 FROM requested r
 LEFT JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=$1
 JOIN entity_source_contexts m ON m.tenant_id=$1 AND m.context_id=r.context_id AND m.anchor_entity_id=r.entity_id AND m.source_kind='path_agent'
 JOIN entities node ON (node.tenant_id,node.context_id,node.id)=($1,r.context_id,r.entity_id)
 JOIN entity_agent_contexts a ON (a.tenant_id,a.context_id,a.agent_id)=(m.tenant_id,m.context_id,m.agent_id)
 JOIN tests t ON t.tenant_id=$1 AND t.id=CASE WHEN m.source_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN m.source_ref::uuid END AND t.enabled
 JOIN entity_test_contexts c ON (c.tenant_id,c.context_id,c.test_id)=(m.tenant_id,m.context_id,t.id)
 LEFT JOIN entity_path_test_contexts p ON (p.tenant_id,p.context_id,p.test_id)=(c.tenant_id,c.context_id,c.test_id)
 WHERE m.tenant_id=$1 AND a.tenant_id=$1 AND node.tenant_id=$1 AND c.tenant_id=$1 AND (t.type<>'icmp' OR p.tenant_id=$1)
 AND GREATEST(node.created_at,m.assigned_at,a.assigned_at,c.assigned_at,CASE WHEN t.type='icmp' THEN p.assigned_at ELSE c.assigned_at END,t.updated_at)<=transaction_timestamp()
 AND (m.expires_at IS NULL OR m.expires_at>transaction_timestamp())
 AND (a.expires_at IS NULL OR a.expires_at>transaction_timestamp())
 ORDER BY m.context_id,m.anchor_entity_id,t.id,m.agent_id LIMIT $5`, pgx.QueryExecModeDescribeExec, sc.Tenant.String(), contexts, entities, maxBytes/8, maxBytes/1024+1)
	if err != nil {
		return nil, err
	}
	// Close the cursor before policy callbacks: ABAC denial auditing can use
	// the same connection, and cannot execute while a result cursor is active.
	out := []IncidentConfiguredTest{}
	remaining := maxBytes - int64(len(members))*512
	for rows.Next() {
		var item IncidentConfiguredTest
		var name, target, pathTarget *string
		var params []byte
		if err := rows.Scan(&item.ContextID, &item.EntityID, &item.TestID, &item.AgentID, &item.Type, &name, &target, &pathTarget, &item.CurrentSince, &item.ValidUntil, &item.Definition.IntervalSeconds, &item.Definition.TimeoutSeconds, &params, &item.MeasurementIdentityUntil); err != nil {
			rows.Close()
			return nil, err
		}
		if name == nil || target == nil || pathTarget == nil || len(params) == 0 {
			rows.Close()
			return nil, ErrIncidentImpactBudget
		}
		item.TenantID = sc.Tenant.String()
		item.SourceGeneration = generation
		item.Name, item.Target = *name, *target
		cost := int64(1024+len(item.Name)+len(item.Type)+len(item.Target)+len(item.AgentID)) + 8*int64(len(params))
		if cost > remaining {
			rows.Close()
			return nil, ErrIncidentImpactBudget
		}
		remaining -= cost
		if item.Type == "icmp" && path.TargetHost(*target) != *pathTarget {
			continue
		}
		item.Definition.ID, item.Definition.Type, item.Definition.Target = item.TestID, item.Type, item.Target
		if err := json.Unmarshal(params, &item.Definition.Params); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, item := range out {
		member, found := members[item.ContextID+":"+item.EntityID]
		if !found {
			return nil, entity.ErrScopeMismatch
		}
		record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, item.ContextID)
		if err != nil {
			return nil, err
		}
		if err := authorize(ctx, record, member, item.TestID); err != nil {
			return nil, err
		}
	}
	return out, ctx.Err()
}

// Read snapshots cannot prepare an epoch row. An absent row is the same
// generation-one source state used by complete incident input reads.
func incidentImpactSourceGenerationInScope(ctx context.Context, sc tenancy.Scope) (int64, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return 0, entity.ErrScopeMismatch
	}
	var generation int64
	var invalidating bool
	err := sc.Q.QueryRow(ctx, `SELECT COALESCE(epoch.generation,1),COALESCE(epoch.invalidating OR epoch.observation_erasing,false)
 FROM (VALUES($1::uuid)) tenant(id) LEFT JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=tenant.id`, bound.String()).Scan(&generation, &invalidating)
	if err != nil {
		return 0, err
	}
	if generation <= 0 || invalidating {
		return 0, sourceepoch.ErrInvalidating
	}
	return generation, nil
}
