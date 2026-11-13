// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// IncidentInterfaceStateSource is current operator ownership, not a link-state
// observation or a reusable grant. Historical facts require their independent
// original sender and complete document checks within the same read snapshot.
// A first typed observation may create its canonical interface. CurrentSince
// therefore bounds its operator/source grant, not the later materialization
// time of that interface row. Raw flow/counter birth rules remain separate.
type IncidentInterfaceStateSource struct {
	TenantID, ContextID, EntityID, RouterID, AgentID, ConfiguredRef string
	SourceGeneration                                                int64
	IfIndex                                                         uint32
	CurrentSince                                                    time.Time
	ValidUntil                                                      *time.Time
	Current                                                         bool
	Reason                                                          string
}

// InterfaceStateSourcesInScope reads the complete current interface ownership
// cohort of incident routers before selecting the authorized members. An
// unreadable competing source still cannot make a duplicate ifIndex unique.
// The complete cohort shares one admitted envelope; errors return no prefix.
func (Incidents) InterfaceStateSourcesInScope(ctx context.Context, sc tenancy.Scope, inputs *IncidentImpactInputs, budget entity.InterfaceRolePolicyBudget,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) ([]IncidentInterfaceStateSource, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || inputs == nil || inputs.TenantID != bound.String() || authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	if generation != inputs.SourceGeneration || generation <= 0 {
		return nil, sourceepoch.ErrInvalidating
	}
	if budget.MemoryBytes < 4096 || budget.WorkUnits <= 0 || int64(len(inputs.Entities)) > budget.MemoryBytes/1024 {
		return nil, ErrIncidentImpactBudget
	}
	admission := roleInputAdmission{memory: budget.MemoryBytes, work: budget.WorkUnits}
	if err := admission.charge(ctx, 4096+int64(len(inputs.Entities))*512, int64(len(inputs.Entities))); err != nil {
		return nil, err
	}
	contexts, members := []string{}, []string{}
	records := map[string]entity.ContextRecord{}
	selected := map[string]bool{}
	for _, member := range inputs.Entities {
		if _, err := validRegistryUUID(member.ContextID); err != nil {
			return nil, err
		}
		if _, err := validRegistryUUID(member.EntityID); err != nil {
			return nil, err
		}
		record, known := records[member.ContextID]
		if !known {
			record, err = NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, member.ContextID)
			if err != nil {
				return nil, err
			}
			records[member.ContextID] = record
		}
		if err := authorize(ctx, record, member); err != nil {
			return nil, err
		}
		key := member.ContextID + ":" + member.EntityID
		if selected[key] {
			continue
		}
		selected[key] = true
		contexts, members = append(contexts, member.ContextID), append(members, member.EntityID)
	}
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
 SELECT * FROM unnest($2::uuid[],$3::uuid[]) AS r(context_id,entity_id)),
 routers AS (
 SELECT DISTINCT n.context_id,CASE WHEN n.kind='device' THEN n.id ELSE n.parent_entity_id END AS id
 FROM requested r JOIN entities n ON (n.tenant_id,n.context_id,n.id)=($1,r.context_id,r.entity_id)
 WHERE n.kind IN ('device','interface'))
 SELECT child.context_id::text,child.id::text,parent.id::text,COALESCE(child.source_agent_id,''),
 COALESCE(child.configured_ref,''),COALESCE(child.interface_index,0),
 COALESCE(GREATEST(m.assigned_at,a.assigned_at,epoch.observation_not_before),'epoch'::timestamptz),
 LEAST(m.expires_at,a.expires_at,identity.not_after),
 COALESCE(child.created_at<=transaction_timestamp() AND child.interface_index>0
 AND m.anchor_entity_id=parent.id AND m.assigned_at<=transaction_timestamp()
 AND a.assigned_at<=transaction_timestamp()
 AND (m.expires_at IS NULL OR m.expires_at>transaction_timestamp())
 AND (a.expires_at IS NULL OR a.expires_at>transaction_timestamp())
 AND identity.not_after IS NOT NULL,false)
 FROM routers r JOIN entities parent ON (parent.tenant_id,parent.context_id,parent.id)=($1,r.context_id,r.id) AND parent.kind='device'
 JOIN entities child ON (child.tenant_id,child.context_id,child.parent_entity_id)=($1,parent.context_id,parent.id) AND child.kind='interface'
 LEFT JOIN entity_source_contexts m ON (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=
 (child.tenant_id,child.context_id,child.source_agent_id,'device_target',child.configured_ref)
 LEFT JOIN entity_agent_contexts a ON (a.tenant_id,a.context_id,a.agent_id)=(m.tenant_id,m.context_id,m.agent_id)
 LEFT JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=$1
 LEFT JOIN LATERAL (
 SELECT max(i.not_after) AS not_after FROM agent_identities i
 WHERE i.tenant_id=$1 AND i.agent_id=child.source_agent_id
 AND i.spiffe_id='spiffe://probectl/tenant/'||$1::text||'/entity/'||child.source_agent_id
 AND i.issued_at<=transaction_timestamp() AND i.not_after>transaction_timestamp() AND i.revoked_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM agent_identities revoked WHERE revoked.tenant_id=$1 AND revoked.agent_id=i.agent_id
 AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')) identity ON true
 WHERE child.tenant_id=$1 AND parent.tenant_id=$1
 ORDER BY child.context_id,parent.id,child.interface_index,child.id LIMIT $4`, pgx.QueryExecModeDescribeExec,
		bound.String(), contexts, members, budget.MemoryBytes/1024+1)
	if err != nil {
		return nil, err
	}
	cohort := []IncidentInterfaceStateSource{}
	type interfaceKey struct {
		context, router string
		index           uint32
	}
	owners := map[interfaceKey]int{}
	for rows.Next() {
		var source IncidentInterfaceStateSource
		var index int64
		if err := rows.Scan(&source.ContextID, &source.EntityID, &source.RouterID, &source.AgentID, &source.ConfiguredRef,
			&index, &source.CurrentSince, &source.ValidUntil, &source.Current); err != nil {
			rows.Close()
			return nil, err
		}
		if index < 0 || index > 1<<32-1 {
			rows.Close()
			return nil, entity.ErrInvalidClaim
		}
		if err := admission.charge(ctx, int64(1024+len(source.AgentID)+len(source.ConfiguredRef)), 1); err != nil {
			rows.Close()
			return nil, err
		}
		source.TenantID, source.SourceGeneration, source.IfIndex = bound.String(), generation, uint32(index)
		if source.Current {
			owners[interfaceKey{source.ContextID, source.RouterID, source.IfIndex}]++
		}
		cohort = append(cohort, source)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []IncidentInterfaceStateSource{}
	for _, source := range cohort {
		if !selected[source.ContextID+":"+source.RouterID] && !selected[source.ContextID+":"+source.EntityID] {
			continue
		}
		member := IncidentImpactEntity{ContextID: source.ContextID, EntityID: source.EntityID}
		if err := authorize(ctx, records[source.ContextID], member); err != nil {
			return nil, err
		}
		source.Reason = "unavailable_current_source"
		if source.Current {
			source.Reason = "current_operator_owned_interface"
			if owners[interfaceKey{source.ContextID, source.RouterID, source.IfIndex}] != 1 {
				source.Current, source.Reason = false, "ambiguous_interface_index"
			}
		}
		out = append(out, source)
	}
	return out, ctx.Err()
}
