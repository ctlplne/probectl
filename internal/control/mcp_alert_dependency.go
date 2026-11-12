// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var _ mcp.AlertDependencyBackend = mcpTagMutationBackend{}

func (b mcpTagMutationBackend) AlertDependencyGet(ctx context.Context, actor *auth.Principal, id string) (alert.DependencyPolicyState, error) {
	if b.server == nil {
		return alert.DependencyPolicyState{}, apierror.Unavailable("alert dependency configuration is unavailable")
	}
	return b.server.readAlertDependencyPolicy(ctx, actor, id)
}

func (b mcpTagMutationBackend) AlertDependencySet(ctx context.Context, actor *auth.Principal, input mcp.AlertDependencyInput) (alert.DependencyPolicyState, error) {
	if b.server == nil || input.Input == nil {
		return alert.DependencyPolicyState{}, apierror.Validation("complete dependency configuration is required")
	}
	return b.server.setAlertDependencyPolicy(ctx, actor, input.RuleID, *input.Input)
}

func (b mcpTagMutationBackend) AlertDependencyClear(ctx context.Context, actor *auth.Principal, input mcp.AlertTagFilterClearInput) (alert.DependencyPolicyState, error) {
	if b.server == nil || !input.Confirmed {
		return alert.DependencyPolicyState{}, apierror.Validation("explicit clear confirmation is required")
	}
	return b.server.clearAlertDependencyPolicy(ctx, actor, input.RuleID)
}

func (b mcpTagMutationBackend) AlertDependencyWorkflow(ctx context.Context, actor *auth.Principal, fingerprint string) (*alert.DependencyWorkflow, error) {
	ctx, flush := scopedABACDenial(ctx)
	defer flush(b.server)
	r, err := b.request(ctx, actor, "read", "/v1/alerts/active/"+url.PathEscape(fingerprint)+"/workflow")
	if err != nil {
		return nil, err
	}
	src, _, err := b.server.alertStateFor(r)
	if err != nil {
		return nil, err
	}
	var active *alert.ActiveAlert
	if src != nil {
		for _, item := range src.Active() {
			if item.Fingerprint == fingerprint {
				active = &item
				break
			}
		}
	}
	if active == nil {
		return nil, apierror.NotFound("no active alert with that fingerprint")
	}
	var out *alert.DependencyWorkflow
	err = b.server.inTenant(r.WithContext(tenancy.WithSiloTableLock(r.Context())), func(ctx context.Context, sc tenancy.Scope) error {
		var readErr error
		out, readErr = b.server.dependencyWorkflowInScope(ctx, sc, actor, active)
		return readErr
	})
	return out, err
}

func alertDependencyToolSchemas() (map[string]json.RawMessage, error) {
	id := map[string]any{"type": "string", "format": "uuid"}
	object := func(properties map[string]any, required ...string) any {
		return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
	}
	return alertConfigurationToolSchemas(map[string]any{
		"alert_dependency_workflow": object(map[string]any{"fingerprint": map[string]any{"type": "string", "minLength": 1}}, "fingerprint"),
		"alert_dependency_get":      object(map[string]any{"rule_id": id}, "rule_id"),
		"alert_dependency_set":      object(map[string]any{"rule_id": id, "input": map[string]any{"$ref": "#/components/schemas/AlertDependencyPolicyInput"}}, "rule_id", "input"),
		"alert_dependency_clear":    object(map[string]any{"rule_id": id, "confirmed": map[string]any{"type": "boolean", "const": true}}, "rule_id", "confirmed"),
	})
}
