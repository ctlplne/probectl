// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ConfigPolicyEvaluation struct {
	PolicyVersion string                `json:"policy_version"`
	EvaluatedAt   time.Time             `json:"evaluated_at"`
	Verdicts      []ConfigPolicyVerdict `json:"verdicts"`
}

// PersistConfigPolicyEvaluation adds a single decision to the exact archive
// in the same transaction. Only original positions are stored as witnesses.
func PersistConfigPolicyEvaluation(ctx context.Context, sc tenancy.Scope, archive ConfigVersion, policy ConfigPolicyRevision) (*ConfigPolicyEvaluation, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || tenant.String() != archive.TenantID || sc.Q == nil || archive.Binding == nil {
		return nil, entity.ErrScopeMismatch
	}
	if len(policy.Rules) == 0 {
		return nil, nil
	}
	verdicts, err := EvaluateConfigPolicy(ctx, archive, policy.Rules)
	if err != nil {
		return nil, err
	}
	for i := range verdicts {
		for j := range verdicts[i].OffendingLines {
			verdicts[i].OffendingLines[j].Text = ""
		}
	}
	evaluation := &ConfigPolicyEvaluation{PolicyVersion: policy.Version, EvaluatedAt: time.Now().UTC(), Verdicts: verdicts}
	body, err := json.Marshal(evaluation)
	if err != nil {
		return nil, err
	}
	tag, err := sc.Q.Exec(ctx, `UPDATE device_configs SET config_policy_evaluation=$1::jsonb
		WHERE tenant_id=$2 AND id=$3 AND entity_context_id=$4 AND device_entity_id=$5
		AND content_hash=$6 AND config_policy_evaluation IS NULL`, body, tenant.String(), archive.ID,
		archive.Binding.ContextID, archive.Binding.DeviceEntityID, archive.ContentHash)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, pgx.ErrNoRows
	}
	return evaluation, nil
}

// ReadConfigPolicyEvaluation reads a receipt and its original, currently
// assigned archive through the same tenant snapshot.
func ReadConfigPolicyEvaluation(ctx context.Context, sc tenancy.Scope, archiveID string) (ConfigVersion, *ConfigPolicyEvaluation, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || sc.Q == nil {
		return ConfigVersion{}, nil, entity.ErrScopeMismatch
	}
	archive, err := scanConfigVersion(sc.Q.QueryRow(ctx, `SELECT `+configVersionColumns+`
		FROM device_configs archive WHERE tenant_id=$1 AND id=$2 AND EXISTS (
			SELECT 1 FROM entity_source_contexts source JOIN entity_agent_contexts assignment
			ON (assignment.tenant_id,assignment.agent_id,assignment.context_id)
			=(source.tenant_id,source.agent_id,source.context_id)
			WHERE (source.tenant_id,source.context_id,source.anchor_entity_id,source.agent_id,source.source_kind,source.source_ref,source.assigned_at,assignment.assigned_at)
			=(archive.tenant_id,archive.entity_context_id,archive.device_entity_id,archive.binding_agent_id,'device_target',
				archive.binding_source_ref,archive.binding_source_assigned_at,archive.binding_agent_assigned_at)
			AND source.assigned_at<=statement_timestamp() AND assignment.assigned_at<=statement_timestamp()
			AND (source.expires_at IS NULL OR source.expires_at>statement_timestamp())
			AND (assignment.expires_at IS NULL OR assignment.expires_at>statement_timestamp())
		)`, tenant.String(), archiveID))
	if err != nil {
		return ConfigVersion{}, nil, err
	}
	var body []byte
	if err := sc.Q.QueryRow(ctx, `SELECT config_policy_evaluation FROM device_configs
		WHERE tenant_id=$1 AND id=$2 AND content_hash=$3`, tenant.String(), archive.ID, archive.ContentHash).Scan(&body); err != nil {
		return ConfigVersion{}, nil, err
	}
	if len(body) == 0 {
		return archive, nil, nil
	}
	var result ConfigPolicyEvaluation
	if err := json.Unmarshal(body, &result); err != nil {
		return ConfigVersion{}, nil, err
	}
	if err := attachConfigPolicyWitnesses(ctx, archive, &result); err != nil {
		return ConfigVersion{}, nil, err
	}
	return archive, &result, nil
}

func attachConfigPolicyWitnesses(ctx context.Context, archive ConfigVersion, result *ConfigPolicyEvaluation) error {
	positions := map[int][]*ConfigPolicyLine{}
	for i := range result.Verdicts {
		v := &result.Verdicts[i]
		if v.ArchiveID != archive.ID || v.ArchiveSHA256 != archive.ContentHash || v.RuleRevision != result.PolicyVersion {
			return ErrConfigPolicyRules
		}
		for j := range v.OffendingLines {
			line := &v.OffendingLines[j]
			if line.Number < 1 || line.Text != "" {
				return ErrConfigPolicyRules
			}
			positions[line.Number] = append(positions[line.Number], line)
		}
	}
	if len(positions) == 0 {
		return ctx.Err()
	}
	if hashConfig(archive.Content) != archive.ContentHash || RedactConfig(archive.Content) != archive.Content {
		return ErrConfigPolicyRules
	}
	scan := bufio.NewScanner(strings.NewReader(archive.Content))
	scan.Buffer(make([]byte, 4096), 16<<10)
	for n := 1; len(positions) > 0 && scan.Scan(); n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, witness := range positions[n] {
			witness.Text = scan.Text()
		}
		delete(positions, n)
	}
	if len(positions) > 0 {
		return ErrConfigPolicyRules
	}
	return ctx.Err()
}
