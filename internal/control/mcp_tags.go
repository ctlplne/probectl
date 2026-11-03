// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var _ mcp.TagBackend = mcpTagBackend{}

type mcpTagBackend struct {
	pool         *pgxpool.Pool
	policyLoader mcp.PolicyLoader
}

func (b mcpTagBackend) TagDefinitionList(ctx context.Context, p *auth.Principal) (mcp.TagDefinitionListResult, error) {
	if p == nil || p.TenantID == "" {
		return mcp.TagDefinitionListResult{}, apierror.Forbidden("tenant identity is required")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(p.TenantID))
	out := mcp.TagDefinitionListResult{Items: []mcp.TagDefinitionResult{}}
	err := tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		items, err := (store.TagDefinitions{}).List(ctx, sc)
		if err != nil {
			return err
		}
		for _, item := range items {
			out.Items = append(out.Items, mcp.TagDefinitionResult{ID: item.ID, Key: item.Key})
		}
		return nil
	})
	if err != nil {
		return mcp.TagDefinitionListResult{}, tagDefinitionAPIError(err)
	}
	return out, nil
}

func (b mcpTagBackend) tagContext(ctx context.Context, p *auth.Principal,
	contextID string) (context.Context, string, error) {
	ctx, scope, err := entityMCPContext(ctx, p, contextID)
	if err != nil {
		return nil, "", err
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	if err := checker.requireEntityContext(ctx, p, scope, permTagsRead); err != nil {
		return nil, "", err
	}
	return ctx, scope.ContextID, nil
}

func (b mcpTagBackend) TagRuleList(ctx context.Context, p *auth.Principal,
	input mcp.TagContextListInput) (mcp.TagRuleListResult, error) {
	ctx, contextID, err := b.tagContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.TagRuleListResult{}, err
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	out := mcp.TagRuleListResult{ContextID: contextID, Items: []mcp.TagRuleResult{}}
	err = tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		items, next, err := (store.TagRules{}).List(ctx, sc, contextID, input.Cursor, input.Limit)
		if err != nil {
			return err
		}
		out.NextCursor = next
		for _, item := range items {
			out.Items = append(out.Items, mcpTagRule(item))
		}
		return nil
	})
	if err != nil {
		return mcp.TagRuleListResult{}, tagRuleAPIError(err)
	}
	return out, nil
}

func (b mcpTagBackend) TagAssignmentList(ctx context.Context, p *auth.Principal,
	input mcp.TagContextListInput) (mcp.TagAssignmentListResult, error) {
	ctx, contextID, err := b.tagContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.TagAssignmentListResult{}, err
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	out := mcp.TagAssignmentListResult{ContextID: contextID,
		Items: []mcp.TagAssignmentResult{}}
	err = tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		items, next, err := (store.TagAssignments{}).List(ctx, sc, contextID,
			input.Cursor, input.Limit)
		if err != nil {
			return err
		}
		out.NextCursor = next
		for _, item := range items {
			out.Items = append(out.Items, mcpTagAssignment(item))
		}
		return nil
	})
	if err != nil {
		return mcp.TagAssignmentListResult{}, tagAssignmentAPIError(err)
	}
	return out, nil
}

func mcpTagAssignment(item store.TagAssignmentRecord) mcp.TagAssignmentResult {
	targetID := item.TargetID
	if item.TargetKind == "exporter" {
		// The encoded target contains an agent and source reference. Keep it
		// on the authenticated REST plane only.
		targetID = ""
	}
	return mcp.TagAssignmentResult{ID: item.ID, TagID: item.TagID,
		TargetKind: item.TargetKind, TargetID: targetID,
		Value: item.Value, Source: item.Source}
}
