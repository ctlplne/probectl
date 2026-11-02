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

type NetBoxTagPreviewInput struct {
	ContextID         string `json:"context_id"`
	TagID             string `json:"tag_id"`
	ExporterAgentID   string `json:"exporter_agent_id"`
	ExporterSourceRef string `json:"exporter_source_ref"`
	Field             string `json:"field"`
}

// This source projection requires cmdb.read in addition to tags.read. It
// omits the encoded exporter target and packet address from result fields.
type NetBoxTagPreviewResult struct {
	ContextID      string `json:"context_id"`
	TagID          string `json:"tag_id"`
	TagKey         string `json:"tag_key"`
	TagRevision    string `json:"tag_revision"`
	NetBoxTenantID string `json:"netbox_tenant_id"`
	LookupCIID     string `json:"lookup_ci_id"`
	CIID           string `json:"ci_id"`
	Name           string `json:"name"`
	Field          string `json:"field"`
	Value          string `json:"value"`
	SourceRef      string `json:"source_ref"`
}

type NetBoxTagBackend interface {
	NetBoxTagPreview(context.Context, *auth.Principal, NetBoxTagPreviewInput) (NetBoxTagPreviewResult, error)
}

func WithNetBoxTagBackend(backend NetBoxTagBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tool := Tool{Name: "tag_netbox_preview", Permission: "tags.read",
			ExtraPermissions: []string{"cmdb.read"}, RequiresUser: true,
			Description: "Preview a fresh mapped NetBox role/site value for an owned exporter; writes no assignment.",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["context_id","tag_id","exporter_agent_id","exporter_source_ref","field"],"properties":{"context_id":{"type":"string","format":"uuid"},"tag_id":{"type":"string","format":"uuid"},"exporter_agent_id":{"type":"string","maxLength":128},"exporter_source_ref":{"type":"string","maxLength":45},"field":{"type":"string","enum":["role","site"]}}}`),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input NetBoxTagPreviewInput
				if err := decodeNativeArgs(raw, &input); err != nil {
					return nil, argErr("invalid NetBox tag preview arguments")
				}
				return backend.NetBoxTagPreview(ctx, p, input)
			}}
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
