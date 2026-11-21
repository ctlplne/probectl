// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrConfigPolicyChanged = errors.New("device configuration policy revision changed")

type ConfigPolicyRevision struct {
	Version     string             `json:"version"`
	PublishedAt time.Time          `json:"published_at"`
	Rules       []ConfigPolicyRule `json:"rules"`
}

// LatestConfigPolicy reads the active configuration rules through the
// tenant transaction selected by the caller.
func LatestConfigPolicy(ctx context.Context, sc tenancy.Scope, binding ConfigArchiveBinding) (ConfigPolicyRevision, error) {
	tid, ok := tenancy.FromContext(ctx)
	if !ok || tid != sc.Tenant || sc.Q == nil {
		return ConfigPolicyRevision{}, entity.ErrScopeMismatch
	}
	current, err := normalizeConfigBinding(tid.String(), &binding)
	if err != nil {
		return ConfigPolicyRevision{}, err
	}
	if err := requireConfigPolicySource(ctx, sc, *current); err != nil {
		return ConfigPolicyRevision{}, err
	}
	var result ConfigPolicyRevision
	var version int64
	var body []byte
	err = sc.Q.QueryRow(ctx, `
		SELECT version, published_at, rules FROM device_config_policy_revisions
		 WHERE tenant_id=$1 AND context_id=$2 AND device_entity_id=$3
		 ORDER BY version DESC LIMIT 1`, tid.String(), current.ContextID, current.DeviceEntityID).
		Scan(&version, &result.PublishedAt, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConfigPolicyRevision{Version: "0", Rules: []ConfigPolicyRule{}}, nil
	}
	if err != nil {
		return ConfigPolicyRevision{}, err
	}
	if err := json.Unmarshal(body, &result.Rules); err != nil {
		return ConfigPolicyRevision{}, err
	}
	result.Version = strconv.FormatInt(version, 10)
	result.PublishedAt = result.PublishedAt.UTC()
	return result, nil
}

// PublishConfigPolicy appends an immutable revision. A caller must authorize
// the device and append the audit event in the same tenant writer transaction.
func PublishConfigPolicy(ctx context.Context, sc tenancy.Scope, binding ConfigArchiveBinding, expected string, raw []ConfigPolicyRule) (ConfigPolicyRevision, error) {
	tid, ok := tenancy.FromContext(ctx)
	if !ok || tid != sc.Tenant || sc.Q == nil {
		return ConfigPolicyRevision{}, entity.ErrScopeMismatch
	}
	current, err := normalizeConfigBinding(tid.String(), &binding)
	if err != nil {
		return ConfigPolicyRevision{}, err
	}
	previous, err := strconv.ParseInt(expected, 10, 64)
	if err != nil || previous < 0 || previous == math.MaxInt64 || strconv.FormatInt(previous, 10) != expected {
		return ConfigPolicyRevision{}, ErrConfigPolicyRules
	}
	next := previous + 1
	result := ConfigPolicyRevision{Version: strconv.FormatInt(next, 10)}
	result.Rules, err = normalizeConfigPolicyRules(raw, result.Version)
	if err != nil {
		return ConfigPolicyRevision{}, err
	}
	body, err := json.Marshal(result.Rules)
	if err != nil {
		return ConfigPolicyRevision{}, err
	}
	// Serialize policy edits even when different original sources represent
	// the same canonical device. Archive source locks do not acquire this key.
	key := "device-config-policy/" + tid.String() + "/" + current.ContextID + "/" + current.DeviceEntityID
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
		return ConfigPolicyRevision{}, err
	}
	source := ConfigVersion{TenantID: tid.String(), Binding: current}
	if err := bindConfigArchiveInScope(ctx, sc, &source); err != nil {
		return ConfigPolicyRevision{}, err
	}
	policy, err := LatestConfigPolicy(ctx, sc, *current)
	if err != nil {
		return ConfigPolicyRevision{}, err
	}
	if policy.Version != expected {
		return ConfigPolicyRevision{}, ErrConfigPolicyChanged
	}
	err = sc.Q.QueryRow(ctx, `
		INSERT INTO device_config_policy_revisions(tenant_id, context_id, device_entity_id, version, rules)
		VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING published_at`,
		tid.String(), current.ContextID, current.DeviceEntityID, next, body).Scan(&result.PublishedAt)
	if err != nil {
		return ConfigPolicyRevision{}, err
	}
	result.PublishedAt = result.PublishedAt.UTC()
	return result, nil
}

func requireConfigPolicySource(ctx context.Context, sc tenancy.Scope, binding ConfigArchiveBinding) error {
	var exists bool
	err := sc.Q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM entity_source_contexts source
		JOIN entity_agent_contexts assignment
		ON (assignment.tenant_id,assignment.agent_id,assignment.context_id)=(source.tenant_id,source.agent_id,source.context_id)
		JOIN entities node
		ON (node.tenant_id,node.context_id,node.id,node.kind)=(source.tenant_id,source.context_id,source.anchor_entity_id,'device')
		WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.anchor_entity_id=$3
		AND source.agent_id=$4 AND source.source_kind='device_target' AND source.source_ref=$5
		AND source.assigned_at<=statement_timestamp() AND assignment.assigned_at<=statement_timestamp()
		AND (source.expires_at IS NULL OR source.expires_at>statement_timestamp())
		AND (assignment.expires_at IS NULL OR assignment.expires_at>statement_timestamp()))`,
		sc.Tenant.String(), binding.ContextID, binding.DeviceEntityID, binding.AgentID, binding.SourceRef).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return pgx.ErrNoRows
	}
	return nil
}

func normalizeConfigPolicyRules(raw []ConfigPolicyRule, revision string) ([]ConfigPolicyRule, error) {
	if len(raw) > 128 {
		return nil, ErrConfigPolicyRules
	}
	seen := make(map[string]bool, len(raw))
	rules := make([]ConfigPolicyRule, len(raw))
	for i, rule := range raw {
		if rule.ID == "" || len(rule.ID) > 64 || strings.IndexFunc(rule.ID, func(c rune) bool {
			return (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_'
		}) >= 0 || rule.Revision != "" || seen[rule.ID] || !validConfigPolicyRule(rule) {
			return nil, ErrConfigPolicyRules
		}
		seen[rule.ID] = true
		rule.Revision = revision
		rules[i] = rule
	}
	return rules, nil
}
