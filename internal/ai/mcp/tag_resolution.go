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
	"github.com/ctlplne/probectl/internal/tags"
)

type TagSubjectInput struct {
	ContextID         string `json:"context_id"`
	TargetKind        string `json:"target_kind"`
	TargetID          string `json:"target_id,omitempty"`
	ExporterAgentID   string `json:"exporter_agent_id,omitempty"`
	ExporterSourceRef string `json:"exporter_source_ref,omitempty"`
}

type TagSubjectBackend interface {
	TagSubjectResolve(context.Context, *auth.Principal, TagSubjectInput) (tags.SubjectResolution, error)
}

func WithTagSubjectBackend(backend TagSubjectBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tool := Tool{Name: "tag_subject_resolve", Permission: "tags.read", RequiresUser: true,
			Description: "Resolve effective tags for an owned current subject; requires the subject read grant and current context policy; raw facts and exporter source identities are omitted.",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["context_id","target_kind"],"properties":{"context_id":{"type":"string","format":"uuid"},"target_kind":{"type":"string","enum":["device","interface","prefix","agent","test","exporter"]},"target_id":{"type":"string","maxLength":128},"exporter_agent_id":{"type":"string","maxLength":128},"exporter_source_ref":{"type":"string","maxLength":128}}}`),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input TagSubjectInput
				if err := decodeNativeArgs(raw, &input); err != nil {
					return nil, argErr("invalid effective tag subject arguments")
				}
				return backend.TagSubjectResolve(ctx, p, input)
			}}
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
