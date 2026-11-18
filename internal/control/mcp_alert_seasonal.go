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
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (b mcpTagMutationBackend) AlertSeasonalSourceGet(ctx context.Context, actor *auth.Principal, id string) (alert.SeasonalSourceState, error) {
	if b.server == nil {
		return alert.SeasonalSourceState{}, apierror.Unavailable("seasonal alert sources are unavailable")
	}
	state, err := b.server.getAlertSeasonalSource(ctx, actor, id, mcp.CheckOriginatingCredential)
	if err != nil {
		return alert.SeasonalSourceState{}, alertSeasonalError(err)
	}
	return b.server.retainNativeSeasonalSource(ctx, actor, state, permAlertRead)
}

func (b mcpTagMutationBackend) AlertSeasonalSourceSet(ctx context.Context, actor *auth.Principal, id string, input *alert.SeasonalBaselineInput) (alert.SeasonalSourceState, error) {
	if b.server == nil {
		return alert.SeasonalSourceState{}, apierror.Unavailable("seasonal alert sources are unavailable")
	}
	state, err := b.server.setAlertSeasonalSource(ctx, actor, id, input, mcp.CheckOriginatingCredential)
	if err != nil {
		return alert.SeasonalSourceState{}, alertSeasonalError(err)
	}
	return b.server.retainNativeSeasonalSource(ctx, actor, state, permAlertWrite)
}

func (s *Server) retainNativeSeasonalSource(ctx context.Context, actor *auth.Principal, state alert.SeasonalSourceState, permission string) (alert.SeasonalSourceState, error) {
	check := func(ctx context.Context) error {
		ctx, rule, err := s.beginAlertSeasonalSource(ctx, actor, state.RuleID, permission, mcp.CheckOriginatingCredential)
		if err != nil {
			return err
		}
		if !rule.UpdatedAt.Equal(state.RuleUpdatedAt) || rule.HasSeasonalSource != state.Configured {
			return store.ErrAlertSeasonalChanged
		}
		if state.Configured {
			return s.revalidateNativeSeasonalRead(ctx, actor, rule, state)
		}
		return ctx.Err()
	}
	if err := mcp.RetainNativePublication(ctx, check, func() {}); err != nil {
		return alert.SeasonalSourceState{}, err
	}
	return state, nil
}

func (s *Server) revalidateNativeSeasonalRead(ctx context.Context, actor *auth.Principal, rule *alert.Rule, state alert.SeasonalSourceState) error {
	if err := s.authorizeSeasonalMetricRead(ctx, actor); err != nil {
		return err
	}
	if state.Source == nil || state.Source.TestID == "" {
		return ctx.Err()
	}
	stored, err := s.loadSeasonalRuleSource(ctx, *rule, flowstore.ExplorerOperationBudget(ctx, s.flowStore).MemoryBytes/8)
	if err != nil {
		return err
	}
	_, err = s.seasonalTestRevision(ctx, actor, stored.Config.TestID, stored.TestRevision)
	return err
}

func alertSeasonalToolSchemas() (map[string]json.RawMessage, error) {
	id := map[string]any{"type": "string", "format": "uuid"}
	object := func(properties map[string]any, required ...string) any {
		return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
	}
	return alertConfigurationToolSchemas(map[string]any{
		"alert_seasonal_source_get":   object(map[string]any{"rule_id": id}, "rule_id"),
		"alert_seasonal_source_set":   object(map[string]any{"rule_id": id, "input": map[string]any{"$ref": "#/components/schemas/AlertSeasonalSourceInput"}}, "rule_id", "input"),
		"alert_seasonal_source_clear": object(map[string]any{"rule_id": id, "confirmed": map[string]any{"type": "boolean", "const": true}}, "rule_id", "confirmed"),
	})
}
