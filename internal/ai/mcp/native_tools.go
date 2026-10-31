// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

// NativeFlowSchemas contains trusted schemas derived from the committed API,
// never a schema supplied by an MCP client.
type NativeFlowSchemas map[string]json.RawMessage
type NativeFlowAdmission func(context.Context, *auth.Principal) (func(), error)

func WithNativeFlowBackend(backend NativeFlowBackend, schemas NativeFlowSchemas, admit NativeFlowAdmission) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tools := buildNativeFlowTools(backend, schemas)
		for _, tool := range tools {
			if !json.Valid(tool.InputSchema) {
				s.log.Error("native flow tool schema is unavailable", "tool", tool.Name)
				return
			}
		}
		s.nativeEnabled = true
		for _, tool := range tools {
			if tool.Query && admit != nil {
				tool.Admit = admit
			}
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}
func nativeFlowTool[A, R any](name, description string, schema json.RawMessage, write string, query bool, invoke func(context.Context, *auth.Principal, A) (R, error)) Tool {
	var contract struct {
		Required []string `json:"required"`
	}
	_ = json.Unmarshal(schema, &contract)
	permissions := []string{"ai.query"}
	if write != "" {
		permissions = append(permissions, write)
	}
	return Tool{Name: name, Description: description, InputSchema: schema, Permission: "flow.read", ExtraPermissions: permissions, Native: true, RequiresUser: true, Query: query, Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
		var fields map[string]json.RawMessage
		if len(raw) > 0 && json.Unmarshal(raw, &fields) != nil {
			return nil, apierror.Validation("invalid native arguments")
		}
		for _, name := range contract.Required {
			value, ok := fields[name]
			if !ok || strings.TrimSpace(string(value)) == "null" {
				return nil, apierror.Validation("required native argument is missing")
			}
		}
		var input A
		if err := decodeNativeArgs(raw, &input); err != nil {
			return nil, apierror.Validation("invalid native arguments")
		}
		return invoke(ctx, p, input)
	}}
}

type nativeFlowQueryArgs struct {
	Plan flow.QueryPlan `json:"plan"`
}
type nativeFlowCursorArgs struct {
	Cursor string `json:"cursor"`
}
type nativeFlowIDArgs struct {
	ID string `json:"id"`
}
type nativeFlowDeleteArgs struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type nativeFlowFilterListArgs struct {
	After string `json:"after"`
	Limit int    `json:"limit"`
}
type nativeFlowFavoriteArgs struct {
	ID       string `json:"id"`
	Favorite *bool  `json:"favorite"`
}

func buildNativeFlowTools(b NativeFlowBackend, schemas NativeFlowSchemas) []Tool {
	return []Tool{
		nativeFlowTool("flow_explorer_plan", "Propose a native flow query from a question without reading telemetry or storing conversation history. Review the proposal, then explicitly call flow_explorer_query or flow_explorer_compare to execute under current permissions.", schemas["flow_explorer_plan"], "", true, b.FlowPlan),
		nativeFlowTool("flow_explorer_schema", "Discover the native flow registry, all operators/metrics and source/cost limits. No user SQL.", schemas["flow_explorer_schema"], "", false, func(ctx context.Context, p *auth.Principal, _ struct{}) (NativeFlowSchemaResult, error) {
			return b.FlowSchema(ctx, p)
		}),
		nativeFlowTool("flow_explorer_query", "Execute the same structured native flow plan as REST/CLI/UI. Up to8dimensions,40chart series,350chart detail rows or50000paged table rows within retention; exact decimal values, no SQL.", schemas["flow_explorer_query"], "", true, func(ctx context.Context, p *auth.Principal, a nativeFlowQueryArgs) (NativeFlowQueryResult, error) {
			return b.FlowQuery(ctx, p, a.Plan)
		}),
		nativeFlowTool("flow_explorer_compare", "Compare a native flow plan with any explicit previous period, retaining both exact source periods and frozen paging.", schemas["flow_explorer_compare"], "", true, b.FlowCompare),
		nativeFlowTool("flow_explorer_page", "Read the next creator-private frozen flow page. Accepts only its opaque cursor; rechecks current grants and source/lifecycle validity.", schemas["flow_explorer_page"], "", true, func(ctx context.Context, p *auth.Principal, a nativeFlowCursorArgs) (NativeFlowQueryResult, error) {
			return b.FlowPage(ctx, p, a.Cursor)
		}),
		nativeFlowTool("flow_explorer_comparison_page", "Read the next creator-private frozen comparison page with both source periods. No plan overrides.", schemas["flow_explorer_comparison_page"], "", true, func(ctx context.Context, p *auth.Principal, a nativeFlowCursorArgs) (NativeFlowComparisonResult, error) {
			return b.FlowComparisonPage(ctx, p, a.Cursor)
		}),
		nativeFlowTool("flow_explorer_csv", "Export all frozen query/comparison CSV records, including Other/totals. Follow next_record until absent; columns are repeated per page. Whole cells are redacted, never split into opaque bytes. source_sha256/bytes describe the complete original authenticated CSV, not a checksum of redacted MCP output.", schemas["flow_explorer_csv"], "", true, b.FlowCSV),
		nativeFlowTool("flow_filter_list", "List reusable filters in the authenticated tenant, reauthorizing nested referenced fields. Page until next is absent.", schemas["flow_filter_list"], "", false, func(ctx context.Context, p *auth.Principal, a nativeFlowFilterListArgs) (NativeFlowFilterPage, error) {
			return b.FlowFilters(ctx, p, a.After, a.Limit)
		}),
		nativeFlowTool("flow_filter_get", "Read one authorized reusable native flow filter and its exact decimal revision.", schemas["flow_filter_get"], "", false, func(ctx context.Context, p *auth.Principal, a nativeFlowIDArgs) (NativeFlowFilter, error) {
			return b.FlowFilter(ctx, p, a.ID)
		}),
		nativeFlowTool("flow_filter_save", "Create or update a reusable filter. Updates require id and exact observed revision; references/cycles/quota and immutable audit are enforced.", schemas["flow_filter_save"], "flow.filters.write", false, b.SaveFlowFilter),
		nativeFlowTool("flow_filter_delete", "Delete a tenant-owned reusable filter using its exact observed revision; audited and fail closed.", schemas["flow_filter_delete"], "flow.filters.write", false, func(ctx context.Context, p *auth.Principal, a nativeFlowDeleteArgs) (NativeFlowMutationResult, error) {
			return b.DeleteFlowFilter(ctx, p, a.ID, a.Version)
		}),
		nativeFlowTool("flow_view_list", "List private and explicitly tenant-shared saved flow queries with subject-private favorites/recents, search, labels and sorts.", schemas["flow_view_list"], "", false, b.FlowViews),
		nativeFlowTool("flow_view_get", "Read a private owned or explicitly tenant-shared saved flow query; source permissions are rechecked.", schemas["flow_view_get"], "", false, func(ctx context.Context, p *auth.Principal, a nativeFlowIDArgs) (NativeFlowView, error) {
			return b.FlowView(ctx, p, a.ID)
		}),
		nativeFlowTool("flow_view_save", "Create/update a complete saved flow query including display/comparison/refresh choices. Updates require owner identity and exact revision; tenant sharing never grants writes.", schemas["flow_view_save"], "flow.views.write", false, b.SaveFlowView),
		nativeFlowTool("flow_view_delete", "Delete an owned saved flow query using its exact observed revision. Shared readers cannot delete it.", schemas["flow_view_delete"], "flow.views.write", false, func(ctx context.Context, p *auth.Principal, a nativeFlowDeleteArgs) (NativeFlowMutationResult, error) {
			return b.DeleteFlowView(ctx, p, a.ID, a.Version)
		}),
		nativeFlowTool("flow_view_favorite", "Set a personal favorite on an authorized saved flow query; affects only the authenticated subject.", schemas["flow_view_favorite"], "", false, func(ctx context.Context, p *auth.Principal, a nativeFlowFavoriteArgs) (NativeFlowMutationResult, error) {
			if a.Favorite == nil {
				return NativeFlowMutationResult{}, apierror.Validation("favorite is required")
			}
			return b.FavoriteFlowView(ctx, p, a.ID, *a.Favorite)
		}),
		nativeFlowTool("flow_view_run", "Run an authorized stored query without overrides, materializing relative windows once and recording subject-private recency. Returns exact query or comparison data.", schemas["flow_view_run"], "", true, func(ctx context.Context, p *auth.Principal, a nativeFlowIDArgs) (NativeFlowExecution, error) {
			return b.RunFlowView(ctx, p, a.ID)
		}),
	}
}
