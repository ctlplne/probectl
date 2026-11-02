// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/auth"
)

type NetBoxTagApplyInput struct {
	Confirmed         bool                   `json:"confirmed"`
	ExporterAgentID   string                 `json:"exporter_agent_id"`
	ExporterSourceRef string                 `json:"exporter_source_ref"`
	Preview           NetBoxTagPreviewResult `json:"preview"`
}

type NetBoxTagApplyResult struct {
	AssignmentID string `json:"assignment_id"`
	ContextID    string `json:"context_id"`
	TagID        string `json:"tag_id"`
	Value        string `json:"value"`
	SourceRef    string `json:"source_ref"`
	ReviewedAt   string `json:"reviewed_at"`
}

type NetBoxTagApplyBackend interface {
	NetBoxTagApply(context.Context, *auth.Principal, NetBoxTagApplyInput) (NetBoxTagApplyResult, error)
}

func WithNetBoxTagApplyBackend(backend NetBoxTagApplyBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tool := Tool{Name: "tag_netbox_apply", Permission: "tags.write",
			ExtraPermissions: []string{"tags.read", "cmdb.read"}, RequiresUser: true,
			Description: "Apply only an explicitly confirmed unchanged NetBox preview; source, target, revision and audit are rechecked. Manual assignments retain precedence.",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["confirmed","exporter_agent_id","exporter_source_ref","preview"],"properties":{"confirmed":{"type":"boolean","const":true},"exporter_agent_id":{"type":"string","maxLength":128},"exporter_source_ref":{"type":"string","maxLength":45},"preview":{"type":"object","additionalProperties":false,"required":["context_id","tag_id","tag_key","tag_revision","netbox_tenant_id","lookup_ci_id","ci_id","name","field","value","source_ref"],"properties":{"context_id":{"type":"string","format":"uuid"},"tag_id":{"type":"string","format":"uuid"},"tag_key":{"type":"string","maxLength":64},"tag_revision":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":19},"netbox_tenant_id":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":19},"lookup_ci_id":{"type":"string","maxLength":128},"ci_id":{"type":"string","maxLength":128},"name":{"type":"string","maxLength":256},"field":{"type":"string","enum":["role","site"]},"value":{"type":"string","maxLength":128},"source_ref":{"type":"string","maxLength":128,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"}}}}}`),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input NetBoxTagApplyInput
				if err := decodeNativeArgs(raw, &input); err != nil || !input.Confirmed {
					return nil, argErr("an explicitly confirmed unchanged NetBox preview is required")
				}
				return backend.NetBoxTagApply(ctx, p, input)
			}}
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
