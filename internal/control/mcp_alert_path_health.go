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

var _ mcp.AlertPathHealthBackend = mcpTagMutationBackend{}

func (b mcpTagMutationBackend) AlertPathHealthCreate(ctx context.Context, actor *auth.Principal, input alert.PathHealthRuleInput) (alert.Rule, error) {
	if b.server == nil {
		return alert.Rule{}, apierror.Unavailable("path-health alerts are unavailable")
	}
	req := alertRequest{Name: input.Name, Enabled: input.Enabled, PathHealthSource: &input.PathHealthSource, ForN: input.ForN, RenotifySeconds: input.RenotifySeconds, Severity: input.Severity, Channels: input.Channels}
	rule, err := req.toRule()
	if err != nil {
		return alert.Rule{}, err
	}
	if err := rejectUnresolvedRedactedSecrets(&rule); err != nil {
		return alert.Rule{}, err
	}
	created, err := b.server.createPathHealthAlertRule(ctx, actor, rule, input.PathHealthSource, mcp.CheckOriginatingCredential, mcp.RetainNativePublication)
	if err != nil {
		return alert.Rule{}, err
	}
	return redactRule(created), nil
}

func (b mcpTagMutationBackend) AlertPathHealthGet(ctx context.Context, actor *auth.Principal, id string) (alert.PathHealthSourceState, error) {
	if b.server == nil {
		return alert.PathHealthSourceState{}, apierror.Unavailable("path-health alerts are unavailable")
	}
	return b.server.readAlertPathHealthSource(ctx, actor, id, mcp.CheckOriginatingCredential, mcp.RetainNativePublication)
}

func (b mcpTagMutationBackend) AlertPathHealthSet(ctx context.Context, actor *auth.Principal, input mcp.AlertPathHealthInput) (alert.PathHealthSourceState, error) {
	if b.server == nil || input.Input == nil {
		return alert.PathHealthSourceState{}, apierror.Validation("a complete path-health source is required")
	}
	return b.server.setAlertPathHealthSource(ctx, actor, input.RuleID, *input.Input, mcp.CheckOriginatingCredential, mcp.RetainNativePublication)
}

func (b mcpTagMutationBackend) AlertPathHealthClear(ctx context.Context, actor *auth.Principal, input mcp.AlertTagFilterClearInput) (alert.PathHealthSourceState, error) {
	if b.server == nil || !input.Confirmed {
		return alert.PathHealthSourceState{}, apierror.Validation("explicit clear confirmation is required")
	}
	return b.server.clearAlertPathHealthSource(ctx, actor, input.RuleID, mcp.CheckOriginatingCredential)
}

func alertPathHealthToolSchemas() (map[string]json.RawMessage, error) {
	id := map[string]any{"type": "string", "format": "uuid"}
	object := func(properties map[string]any, required ...string) any {
		return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
	}
	return alertConfigurationToolSchemas(map[string]any{
		"alert_path_health_create": map[string]any{"$ref": "#/components/schemas/PathHealthAlertCreateInput"},
		"alert_path_health_get":    object(map[string]any{"rule_id": id}, "rule_id"),
		"alert_path_health_set":    object(map[string]any{"rule_id": id, "input": map[string]any{"$ref": "#/components/schemas/AlertPathHealthSourceInput"}}, "rule_id", "input"),
		"alert_path_health_clear":  object(map[string]any{"rule_id": id, "confirmed": map[string]any{"type": "boolean", "const": true}}, "rule_id", "confirmed"),
	})
}
