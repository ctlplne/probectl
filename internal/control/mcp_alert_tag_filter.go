// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

var _ mcp.AlertTagBackend = mcpTagMutationBackend{}

func (b mcpTagMutationBackend) AlertTagAdmission(ctx context.Context, p *auth.Principal) (func(), error) {
	if b.server == nil || p == nil || p.TenantID == "" || p.UserID == "" {
		return nil, apierror.Unauthorized("a current tenant user is required")
	}
	if b.server.fairnessGate == nil || flowstore.ExplorerOperationBudget(ctx, b.server.flowStore).Validate() != nil {
		return nil, apierror.Unavailable("alert metadata query admission is unavailable")
	}
	return b.server.fairnessGate.BeginQuery(ctx, p.TenantID)
}

func (b mcpTagMutationBackend) AlertTagFilterGet(ctx context.Context, p *auth.Principal, id string) (alert.TagFilterState, error) {
	if _, err := b.request(ctx, p, "read", "/v1/alerts/rules/"+url.PathEscape(id)+"/tag-filter"); err != nil {
		return alert.TagFilterState{}, err
	}
	return readAlertTagFilter(ctx, b.server.pool, b.server.flowStore, p, id)
}

func (b mcpTagMutationBackend) AlertTagFilterSet(ctx context.Context, p *auth.Principal, input mcp.AlertTagFilterInput) (alert.TagFilterState, error) {
	if input.Input == nil {
		return alert.TagFilterState{}, apierror.Validation("complete alert tag input is required")
	}
	r, err := b.request(ctx, p, "update", "/v1/alerts/rules/"+url.PathEscape(input.RuleID)+"/tag-filter")
	if err != nil {
		return alert.TagFilterState{}, err
	}
	return b.server.setAlertTagFilter(r, input.RuleID, *input.Input)
}

func (b mcpTagMutationBackend) AlertTagFilterClear(ctx context.Context, p *auth.Principal, input mcp.AlertTagFilterClearInput) (alert.TagFilterState, error) {
	if !input.Confirmed {
		return alert.TagFilterState{}, apierror.Validation("explicit clear confirmation is required")
	}
	r, err := b.request(ctx, p, "delete", "/v1/alerts/rules/"+url.PathEscape(input.RuleID)+"/tag-filter")
	if err != nil {
		return alert.TagFilterState{}, err
	}
	return b.server.clearAlertTagFilter(r, input.RuleID)
}

func alertTagToolSchemas() (map[string]json.RawMessage, error) {
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
		"alert_tag_filter_get":   object(map[string]any{"rule_id": id}, "rule_id"),
		"alert_tag_filter_set":   object(map[string]any{"rule_id": id, "input": map[string]any{"$ref": "#/components/schemas/AlertTagFilterInput"}}, "rule_id", "input"),
		"alert_tag_filter_clear": object(map[string]any{"rule_id": id, "confirmed": map[string]any{"type": "boolean", "const": true}}, "rule_id", "confirmed"),
	})
}

var _ mcp.AlertEvaluationBackend = mcpTagMutationBackend{}

func (b mcpTagMutationBackend) AlertEvaluations(ctx context.Context, p *auth.Principal, input mcp.AlertEvaluationsInput) (alert.EvaluationsResult, error) {
	r, err := b.request(ctx, p, "read", "/v1/alerts/"+url.PathEscape(input.RuleID)+"/evaluations")
	if err != nil {
		return alert.EvaluationsResult{}, err
	}
	limit := store.MaxAlertEvaluationReceiptsPerSeries
	if input.Limit != nil {
		limit = *input.Limit
	}
	return b.server.readAlertEvaluations(r, input.RuleID, input.Fingerprint, limit)
}

// Derive query constraints directly from the existing REST operation. The
// native tool adds only its canonical owned UUID and closed argument object.
func alertEvaluationToolSchema() (json.RawMessage, error) {
	var document struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string          `json:"name"`
					Schema json.RawMessage `json:"schema"`
				} `json:"parameters"`
			} `json:"get"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	props := map[string]any{"rule_id": map[string]any{"type": "string", "format": "uuid"}}
	for _, parameter := range document.Paths["/v1/alerts/{id}/evaluations"].Get.Parameters {
		if parameter.Name == "fingerprint" || parameter.Name == "limit" {
			props[parameter.Name] = parameter.Schema
		}
	}
	if len(props) != 3 {
		return nil, fmt.Errorf("alert receipt query schemas are unavailable")
	}
	return json.Marshal(map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": []string{"rule_id"}})
}
