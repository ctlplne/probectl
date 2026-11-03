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

type TestTagBackend interface {
	TestTagContext(context.Context, *auth.Principal, tags.TestContextInput) (tags.TestContextResolution, error)
	TestTagAdmission(context.Context, *auth.Principal) (func(), error)
}

func WithTestTagBackend(backend TestTagBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tool := Tool{Name: "test_tag_context", Permission: "tags.read", ExtraPermissions: []string{permTestRead}, RequiresUser: true, Native: true, Query: true, Admit: backend.TestTagAdmission,
			Description: "Read current descriptive tags for exact owned test IDs at one revision, with current test/context policy. Unknown or denied IDs are omitted; no source facts or telemetry labels are returned.",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["test_ids"],"properties":{"test_ids":{"type":"array","items":{"type":"string","maxLength":128}}}}`),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input tags.TestContextInput
				if err := decodeNativeArgs(raw, &input); err != nil {
					return nil, argErr("invalid test tag context arguments")
				}
				return backend.TestTagContext(ctx, p, input)
			}}
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
