// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

var _ mcp.AlertQueryBackend = mcpTagMutationBackend{}

func (b mcpTagMutationBackend) AlertQueryGroupGet(ctx context.Context, p *auth.Principal, input mcp.AlertQueryGroupInput) (alert.QueryGroupInspection, error) {
	if b.server == nil {
		return alert.QueryGroupInspection{}, apierror.Unavailable("saved-query group inspection is unavailable")
	}
	return b.server.readAlertQueryGroup(ctx, p, input.RuleID, input.Group)
}

func (b mcpTagMutationBackend) AlertQueryCreate(ctx context.Context, p *auth.Principal, input alert.QueryRuleInput) (alert.Rule, error) {
	if b.server == nil {
		return alert.Rule{}, apierror.Unavailable("saved-query alerts are unavailable")
	}
	req := alertRequest{Name: input.Name, Enabled: input.Enabled, QuerySource: &input.QuerySource, ForN: input.ForN, RenotifySeconds: input.RenotifySeconds, Severity: input.Severity, Channels: input.Channels}
	rule, err := req.toRule()
	if err != nil {
		return alert.Rule{}, err
	}
	if err := rejectUnresolvedRedactedSecrets(&rule); err != nil {
		return alert.Rule{}, err
	}
	created, err := b.server.createAlertRule(ctx, p, rule, &input.QuerySource, nil)
	if err != nil {
		return alert.Rule{}, err
	}
	return redactRule(created), nil
}

func (b mcpTagMutationBackend) AlertQuerySourceGet(ctx context.Context, p *auth.Principal, id string) (alert.QuerySourceState, error) {
	if b.server == nil {
		return alert.QuerySourceState{}, apierror.Unavailable("saved-query alerts are unavailable")
	}
	return b.server.readAlertQuerySource(ctx, p, id)
}
func (b mcpTagMutationBackend) AlertQuerySourceSet(ctx context.Context, p *auth.Principal, input mcp.AlertQuerySourceInput) (alert.QuerySourceState, error) {
	if b.server == nil || input.Input == nil {
		return alert.QuerySourceState{}, apierror.Validation("saved-query source is required")
	}
	return b.server.setAlertQuerySource(ctx, p, input.RuleID, *input.Input)
}
func (b mcpTagMutationBackend) AlertQuerySourceClear(ctx context.Context, p *auth.Principal, input mcp.AlertTagFilterClearInput) (alert.QuerySourceState, error) {
	if b.server == nil || !input.Confirmed {
		return alert.QuerySourceState{}, apierror.Validation("explicit clear confirmation is required")
	}
	return b.server.clearAlertQuerySource(ctx, p, input.RuleID)
}

func alertQueryToolSchemas() (map[string]json.RawMessage, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	id := map[string]any{"type": "string", "format": "uuid"}
	object := func(properties map[string]any, required ...string) any {
		return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
	}
	return nativeMCPInputSchemas(document.Components.Schemas, map[string]any{
		"alert_query_group_get":    object(map[string]any{"rule_id": id, "group": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}}, "rule_id", "group"),
		"alert_query_create":       map[string]any{"$ref": "#/components/schemas/SavedQueryAlertCreateInput"},
		"alert_query_source_get":   object(map[string]any{"rule_id": id}, "rule_id"),
		"alert_query_source_set":   object(map[string]any{"rule_id": id, "input": map[string]any{"$ref": "#/components/schemas/AlertQuerySourceInput"}}, "rule_id", "input"),
		"alert_query_source_clear": object(map[string]any{"rule_id": id, "confirmed": map[string]any{"type": "boolean", "const": true}}, "rule_id", "confirmed"),
	})
}
