// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type RoutingPolicyArchive struct {
	ConfigVersion
	ValidUntil *time.Time
}

// RoutingPolicyArchiveInScope reads the exact latest archive of an unchanged,
// currently registered sender for one authorized router. Callers must check
// their device read and change-review grants in the same RLS snapshot. Missing
// content or a newer archive refuses the review. An archive is retained evidence
// of configuration, not access to the router or its live control session.
func RoutingPolicyArchiveInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, router, archive string, maxBytes int64,
	authorize func(context.Context, ConfigArchiveBinding) error) (RoutingPolicyArchive, error) {
	none := RoutingPolicyArchive{}
	bound, present := tenancy.FromContext(ctx)
	if !present || sc.Q == nil || authorize == nil || bound != sc.Tenant || bound.String() != scope.TenantID {
		return none, entity.ErrScopeMismatch
	}
	if normalized, err := scope.Normalize(); err != nil || normalized != scope {
		return none, entity.ErrScopeMismatch
	}
	for _, value := range []string{router, archive} {
		if id, err := uuid.Parse(value); err != nil || id == uuid.Nil || id.String() != value {
			return none, ErrConfigBinding
		}
	}
	if maxBytes <= 0 {
		return none, ErrConfigReferenceBudget
	}
	var contentBytes int64
	out := RoutingPolicyArchive{ConfigVersion: ConfigVersion{ID: archive, TenantID: bound.String(), Binding: &ConfigArchiveBinding{
		Kind: "operator_bound_archive", ContextID: scope.ContextID, DeviceEntityID: router,
	}}}
	var asOf time.Time
	err := sc.Q.QueryRow(ctx, `
SELECT c.device,c.source,c.version,c.content_hash,c.previous_hash,c.drifted,c.observed_at,c.archived_at,
       c.binding_agent_id,c.binding_source_ref,c.binding_source_assigned_at,c.binding_agent_assigned_at,c.bound_at,
       octet_length(c.content),statement_timestamp(),LEAST(s.expires_at,a.expires_at)
FROM device_configs c
JOIN entity_source_contexts s ON
 (s.tenant_id,s.context_id,s.anchor_entity_id,s.agent_id,s.source_kind,s.source_ref,s.assigned_at)=
 (c.tenant_id,c.entity_context_id,c.device_entity_id,c.binding_agent_id,'device_target',c.binding_source_ref,c.binding_source_assigned_at)
JOIN entity_agent_contexts a ON
 (a.tenant_id,a.context_id,a.agent_id,a.assigned_at)=(c.tenant_id,c.entity_context_id,c.binding_agent_id,c.binding_agent_assigned_at)
JOIN entities router ON (router.tenant_id,router.context_id,router.id,router.kind)=
 (c.tenant_id,c.entity_context_id,c.device_entity_id,'device')
WHERE c.tenant_id=$1 AND c.entity_context_id=$2 AND c.device_entity_id=$3 AND c.id=$4
 AND s.assigned_at<=statement_timestamp() AND a.assigned_at<=statement_timestamp()
 AND (s.expires_at IS NULL OR s.expires_at>statement_timestamp())
 AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
 AND NOT EXISTS (
  SELECT 1 FROM device_configs newer
  WHERE (newer.tenant_id,newer.entity_context_id,newer.device_entity_id,newer.binding_agent_id,newer.binding_source_ref,
         newer.binding_source_assigned_at,newer.binding_agent_assigned_at)=
        (c.tenant_id,c.entity_context_id,c.device_entity_id,c.binding_agent_id,c.binding_source_ref,
         c.binding_source_assigned_at,c.binding_agent_assigned_at) AND newer.version>c.version
 )`, bound.String(), scope.ContextID, router, archive).Scan(
		&out.Device, &out.Source, &out.Version, &out.ContentHash, &out.PreviousHash, &out.Drifted, &out.ObservedAt, &out.ArchivedAt,
		&out.Binding.AgentID, &out.Binding.SourceRef, &out.Binding.SourceAssignedAt, &out.Binding.AgentAssignedAt, &out.Binding.BoundAt, &contentBytes, &asOf, &out.ValidUntil)
	if err != nil {
		return none, err
	}
	if err := authorize(ctx, *out.Binding); err != nil {
		return none, err
	}
	if contentBytes > maxBytes {
		return none, ErrConfigReferenceBudget
	}
	if contentBytes == 0 || out.ObservedAt.Before(out.Binding.SourceAssignedAt) || out.ObservedAt.Before(out.Binding.AgentAssignedAt) || out.ObservedAt.After(asOf) {
		return none, ErrConfigBinding
	}
	if err := sc.Q.QueryRow(ctx, `SELECT content FROM device_configs
 WHERE tenant_id=$1 AND entity_context_id=$2 AND device_entity_id=$3 AND id=$4
 AND content_hash=$5 AND octet_length(content)=$6`, bound.String(), scope.ContextID, router, archive,
		out.ContentHash, contentBytes).Scan(&out.Content); err != nil {
		return none, err
	}
	return out, ctx.Err()
}

// LockRoutingPolicyArchiveInScope is the write-side archive fence for an
// audited routing review. Acquire the same source and stream locks as archive
// publication, then read the head after any earlier writer has committed.
func LockRoutingPolicyArchiveInScope(ctx context.Context, sc tenancy.Scope, expected ConfigVersion,
	authorize func(context.Context, ConfigArchiveBinding) error) error {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || sc.Q == nil || tenant != sc.Tenant || tenant.String() != expected.TenantID || authorize == nil || expected.Binding == nil {
		return entity.ErrScopeMismatch
	}
	if expected.ID == "" || expected.Version <= 0 || expected.ContentHash == "" || expected.ObservedAt.IsZero() ||
		expected.Binding.SourceAssignedAt.IsZero() || expected.Binding.AgentAssignedAt.IsZero() {
		return ErrConfigBinding
	}
	var isolation, currentTenant, role string
	if err := sc.Q.QueryRow(ctx, `SELECT current_setting('transaction_isolation'),
 COALESCE(current_setting('probectl.tenant_id',true),''), current_user`).Scan(&isolation, &currentTenant, &role); err != nil {
		return err
	}
	if isolation != "read committed" || currentTenant != tenant.String() || role != tenancy.AppRole {
		return ErrConfigBinding
	}
	current := expected
	if err := bindConfigArchiveInScope(ctx, sc, &current); err != nil {
		return err
	}
	binding := current.Binding
	if !binding.SourceAssignedAt.Equal(expected.Binding.SourceAssignedAt) || !binding.AgentAssignedAt.Equal(expected.Binding.AgentAssignedAt) {
		return ErrConfigBinding
	}
	if err := authorize(ctx, *binding); err != nil {
		return err
	}
	if err := lockConfigStream(ctx, sc, current); err != nil {
		return err
	}
	// A lock wait can outlast a source lease even though the assignment rows
	// remain locked. Refresh the clock and authorization before publication.
	if err := bindConfigArchiveInScope(ctx, sc, &current); err != nil {
		return err
	}
	if err := authorize(ctx, *current.Binding); err != nil {
		return err
	}
	var id, digest string
	var version int
	if err := sc.Q.QueryRow(ctx, `SELECT id::text,content_hash,version FROM device_configs
 WHERE tenant_id=$1 AND entity_context_id=$2 AND device_entity_id=$3 AND binding_agent_id=$4 AND binding_source_ref=$5
 AND binding_source_assigned_at=$6 AND binding_agent_assigned_at=$7 ORDER BY version DESC LIMIT 1`,
		tenant.String(), binding.ContextID, binding.DeviceEntityID, binding.AgentID, binding.SourceRef,
		binding.SourceAssignedAt, binding.AgentAssignedAt).Scan(&id, &digest, &version); err != nil {
		return err
	}
	if id != expected.ID || digest != expected.ContentHash || version != expected.Version {
		return ErrConfigBinding
	}
	return ctx.Err()
}
