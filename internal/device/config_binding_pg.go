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

const configVersionColumns = `id::text,tenant_id::text,device,source,version,content,content_hash,previous_hash,drifted,observed_at,archived_at,
 COALESCE(entity_context_id::text,''),COALESCE(device_entity_id::text,''),COALESCE(binding_agent_id,''),COALESCE(binding_source_ref,''),binding_source_assigned_at,binding_agent_assigned_at,bound_at`

// A selected source must currently be assigned to this exact canonical device.
// Offline configured sources may receive an operator archive: this binding does
// not claim collection or confer subsequent read/source authority.
func bindConfigArchiveInScope(ctx context.Context, sc tenancy.Scope, cfg *ConfigVersion) error {
	if cfg.Binding == nil {
		return nil
	}
	binding, err := normalizeConfigBinding(cfg.TenantID, cfg.Binding)
	if err != nil {
		return err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || cfg.TenantID != bound.String() {
		return ErrConfigBinding
	}
	err = sc.Q.QueryRow(ctx, `SELECT source.assigned_at,assignment.assigned_at,clock_timestamp()
 FROM entity_source_contexts source
 JOIN entity_agent_contexts assignment ON (assignment.tenant_id,assignment.agent_id,assignment.context_id)=(source.tenant_id,source.agent_id,source.context_id)
 JOIN entities node ON (node.tenant_id,node.context_id,node.id,node.kind)=(source.tenant_id,source.context_id,source.anchor_entity_id,'device')
 WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.anchor_entity_id=$3
 AND source.agent_id=$4 AND source.source_kind='device_target' AND source.source_ref=$5
 AND source.assigned_at<=statement_timestamp() AND assignment.assigned_at<=statement_timestamp()
 AND (source.expires_at IS NULL OR source.expires_at>statement_timestamp())
 AND (assignment.expires_at IS NULL OR assignment.expires_at>statement_timestamp())
 FOR SHARE OF source,assignment,node`, cfg.TenantID, binding.ContextID, binding.DeviceEntityID, binding.AgentID, binding.SourceRef).Scan(&binding.SourceAssignedAt, &binding.AgentAssignedAt, &binding.BoundAt)
	if err != nil {
		return err
	}
	binding.SourceAssignedAt, binding.AgentAssignedAt, binding.BoundAt = binding.SourceAssignedAt.UTC(), binding.AgentAssignedAt.UTC(), binding.BoundAt.UTC()
	if cfg.ObservedAt.IsZero() {
		cfg.ObservedAt = binding.BoundAt
	}
	if cfg.ObservedAt.Before(binding.SourceAssignedAt) || cfg.ObservedAt.Before(binding.AgentAssignedAt) || cfg.ObservedAt.After(binding.BoundAt) {
		return ErrConfigBinding
	}
	cfg.ArchivedAt, cfg.Binding = binding.BoundAt, binding
	return nil
}

func configStreamArguments(cfg ConfigVersion) []any {
	if cfg.Binding == nil {
		return []any{cfg.TenantID, nil, cfg.Device, nil, nil, nil, nil, nil}
	}
	b := cfg.Binding
	return []any{cfg.TenantID, b.ContextID, cfg.Device, b.DeviceEntityID, b.AgentID, b.SourceRef, b.SourceAssignedAt, b.AgentAssignedAt}
}

// Serialization follows canonical identity/assignment, independently of display
// names. The legacy name-only stream retains its original separate identity.
func lockConfigStream(ctx context.Context, sc tenancy.Scope, cfg ConfigVersion) error {
	key := configStreamArguments(cfg)
	if cfg.Binding != nil {
		key[2] = ""
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		return err
	}
	_, err = sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(encoded))
	return err
}

func scanConfigVersion(row interface{ Scan(...any) error }) (ConfigVersion, error) {
	var cfg ConfigVersion
	var b ConfigArchiveBinding
	var sourceAt, agentAt, boundAt *time.Time
	err := row.Scan(&cfg.ID, &cfg.TenantID, &cfg.Device, &cfg.Source, &cfg.Version, &cfg.Content, &cfg.ContentHash, &cfg.PreviousHash, &cfg.Drifted, &cfg.ObservedAt, &cfg.ArchivedAt,
		&b.ContextID, &b.DeviceEntityID, &b.AgentID, &b.SourceRef, &sourceAt, &agentAt, &boundAt)
	if err != nil {
		return ConfigVersion{}, err
	}
	cfg.ObservedAt, cfg.ArchivedAt = cfg.ObservedAt.UTC(), cfg.ArchivedAt.UTC()
	if b.ContextID != "" {
		if sourceAt == nil || agentAt == nil || boundAt == nil {
			return ConfigVersion{}, ErrConfigBinding
		}
		b.Kind = "operator_bound_archive"
		b.SourceAssignedAt, b.AgentAssignedAt, b.BoundAt = sourceAt.UTC(), agentAt.UTC(), boundAt.UTC()
		cfg.Binding = &b
	}
	return cfg, nil
}
