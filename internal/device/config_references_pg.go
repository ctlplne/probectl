// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ReadConfigArchiveReferences streams the complete admitted interval for one
// exact current assignment, with original predecessors even outside the window.
// The caller separately owns current user/credential and authenticated source
// authority. Assignment epochs prevent a later reassignment inheriting archives.
func (s *PostgresOpsStore) ReadConfigArchiveReferences(ctx context.Context, tenant string, input ConfigArchiveBinding, from, to time.Time, maxBytes int64) ([]ConfigArchiveReference, int64, error) {
	bound, ok := tenancy.FromContext(ctx)
	binding, err := normalizeConfigBinding(tenant, &input)
	if err != nil || !ok || bound.String() != tenant || !to.After(from) || input.SourceAssignedAt.IsZero() || input.AgentAssignedAt.IsZero() {
		return nil, 0, ErrConfigBinding
	}
	if maxBytes < 4096 {
		return nil, 0, ErrConfigReferenceBudget
	}
	binding.SourceAssignedAt, binding.AgentAssignedAt = input.SourceAssignedAt.UTC(), input.AgentAssignedAt.UTC()
	out := []ConfigArchiveReference{}
	var used int64
	err = s.inTenant(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT current.id::text,current.version,current.content_hash,current.previous_hash,current.drifted,current.source,current.observed_at,current.archived_at,current.bound_at,
 COALESCE(previous.id::text,''),COALESCE(previous.version,0)
 FROM device_configs current
 JOIN entity_source_contexts source ON (source.tenant_id,source.context_id,source.anchor_entity_id,source.agent_id,source.source_kind,source.source_ref,source.assigned_at)=
 (current.tenant_id,current.entity_context_id,current.device_entity_id,current.binding_agent_id,'device_target',current.binding_source_ref,current.binding_source_assigned_at)
 JOIN entity_agent_contexts assignment ON (assignment.tenant_id,assignment.agent_id,assignment.context_id,assignment.assigned_at)=
 (current.tenant_id,current.binding_agent_id,current.entity_context_id,current.binding_agent_assigned_at)
 LEFT JOIN device_configs previous ON
 (previous.tenant_id,previous.entity_context_id,previous.device_entity_id,previous.binding_agent_id,previous.binding_source_ref,previous.binding_source_assigned_at,previous.binding_agent_assigned_at)=
 (current.tenant_id,current.entity_context_id,current.device_entity_id,current.binding_agent_id,current.binding_source_ref,current.binding_source_assigned_at,current.binding_agent_assigned_at)
 AND previous.version=current.version-1 AND previous.content_hash=current.previous_hash AND previous.content<>''
 WHERE current.tenant_id=$1 AND current.entity_context_id=$2 AND current.device_entity_id=$3
 AND current.binding_agent_id=$4 AND current.binding_source_ref=$5 AND current.binding_source_assigned_at=$6 AND current.binding_agent_assigned_at=$7
 AND current.observed_at>=$8 AND current.observed_at<=$9 AND current.content<>''
 AND source.assigned_at<=statement_timestamp() AND assignment.assigned_at<=statement_timestamp()
 AND (source.expires_at IS NULL OR source.expires_at>statement_timestamp()) AND (assignment.expires_at IS NULL OR assignment.expires_at>statement_timestamp())
 ORDER BY current.observed_at,current.version,current.id`, tenant, binding.ContextID, binding.DeviceEntityID, binding.AgentID, binding.SourceRef, binding.SourceAssignedAt, binding.AgentAssignedAt, from, to)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			ref := ConfigArchiveReference{Binding: *binding}
			if err := rows.Scan(&ref.ID, &ref.Version, &ref.ContentHash, &ref.PreviousHash, &ref.Drifted, &ref.Source, &ref.ObservedAt, &ref.ArchivedAt, &ref.Binding.BoundAt, &ref.PreviousID, &ref.PreviousVersion); err != nil {
				return err
			}
			ref.ObservedAt, ref.ArchivedAt, ref.Binding.BoundAt = ref.ObservedAt.UTC(), ref.ArchivedAt.UTC(), ref.Binding.BoundAt.UTC()
			ref.ChangeStatus = "no_content_change"
			switch {
			case ref.Version == 1:
				ref.ChangeStatus = "initial_archive"
			case ref.Drifted && ref.PreviousID != "":
				ref.ChangeStatus = "original_predecessor_verified"
			case ref.Drifted:
				ref.ChangeStatus = "unavailable_original_predecessor"
			}
			body, err := json.Marshal(ref)
			if err != nil {
				return err
			}
			cost := int64(4096) + int64(len(body))*8
			if cost > maxBytes-used {
				return ErrConfigReferenceBudget
			}
			used += cost
			out = append(out, ref)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	return out, used, nil
}
