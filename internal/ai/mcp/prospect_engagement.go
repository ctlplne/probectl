// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
)

type ProspectEngagementBackend interface {
	ReadProspectEngagement(context.Context, *auth.Principal) (store.ProspectEngagement, error)
	StartProspectEngagement(context.Context, *auth.Principal, ProspectEngagementStart) (store.ProspectEngagement, error)
	DecideProspectEngagement(context.Context, *auth.Principal, int64, bool) (store.ProspectEngagement, error)
}

// ProspectEngagementStart has no scheduled-erasure consent fields. That
// authorization is only accepted in the interactive tenant session.
type ProspectEngagementStart struct {
	AssessmentViewID string    `json:"assessment_view_id"`
	AssessmentAt     time.Time `json:"assessment_view_revision"`
	Preparer         string    `json:"preparer"`
	EndsAt           time.Time `json:"ends_at"`
}

func WithProspectEngagementBackend(backend ProspectEngagementBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tools := []Tool{{Name: "prospect_engagement_get", Description: "Read the active tenant's current prospect engagement, exact revision, assessment dates and consent state.", Query: true,
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				if err := decodeBoundedNativeArgs(raw, &struct{}{}, min(s.nativeRequestBytes(), 1024)); err != nil {
					return nil, err
				}
				return backend.ReadProspectEngagement(ctx, p)
			}}, {Name: "prospect_engagement_start", Description: "Start an engagement without scheduled erasure in the active tenant. Select an exact owned assessment view.",
			InputSchema: json.RawMessage(`{"type":"object","required":["assessment_view_id","assessment_view_revision","preparer"],"properties":{"assessment_view_id":{"type":"string","minLength":1},"assessment_view_revision":{"type":"string","format":"date-time"},"preparer":{"type":"string","minLength":1},"ends_at":{"type":"string","format":"date-time"}},"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input ProspectEngagementStart
				if err := decodeBoundedNativeArgs(raw, &input, min(s.nativeRequestBytes(), 4096)); err != nil {
					return nil, err
				}
				return backend.StartProspectEngagement(ctx, p, input)
			}}}
		for _, choice := range []struct {
			name, description string
			convert           bool
		}{
			{"prospect_engagement_convert", "Confirm conversion of the current tenant's exact prospect revision to a client. Conversion withdraws scheduled erasure and clears the server's collection deadline.", true},
			{"prospect_engagement_revoke_consent", "Confirm withdrawal of scheduled erasure for the current tenant's exact prospect revision.", false},
		} {
			tools = append(tools, Tool{Name: choice.name, Description: choice.description,
				InputSchema: json.RawMessage(`{"type":"object","required":["revision","confirmed"],"properties":{"revision":{"type":"integer","minimum":1},"confirmed":{"type":"boolean","const":true}},"additionalProperties":false}`),
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					var input struct {
						Revision  int64 `json:"revision"`
						Confirmed bool  `json:"confirmed"`
					}
					if err := decodeBoundedNativeArgs(raw, &input, min(s.nativeRequestBytes(), 1024)); err != nil {
						return nil, err
					}
					if input.Revision < 1 || !input.Confirmed {
						return nil, argErr("the exact current engagement revision and explicit confirmation are required")
					}
					return backend.DecideProspectEngagement(ctx, p, input.Revision, choice.convert)
				}})
		}
		s.nativeEnabled = true
		for _, tool := range tools {
			tool.Permission = "lifecycle.erase"
			tool.Native, tool.RequiresUser = true, true
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}
