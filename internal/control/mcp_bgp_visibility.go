// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type mcpBGPVisibilityBackend struct{ server *Server }

func bgpVisibilityToolOption(server *Server) (mcp.Option, error) {
	var doc struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string          `json:"name"`
					Schema json.RawMessage `json:"schema"`
				} `json:"parameters"`
			} `json:"get"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		return nil, err
	}
	properties := map[string]json.RawMessage{}
	for _, parameter := range doc.Paths["/v1/bgp/visibility/{id}"].Get.Parameters {
		if parameter.Name != "" && json.Valid(parameter.Schema) {
			properties[parameter.Name] = parameter.Schema
		}
	}
	if len(properties) != 3 {
		return nil, apierror.Unavailable("BGP visibility tool contract is unavailable")
	}
	schema, err := json.Marshal(struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}{Type: "object", Properties: properties, Required: []string{"id"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithBGPVisibilityBackend(mcpBGPVisibilityBackend{server}, schema), nil
}

func (b mcpBGPVisibilityBackend) BGPVisibility(ctx context.Context, actor *auth.Principal, command mcp.BGPVisibilityCommand) (json.RawMessage, error) {
	if b.server == nil || b.server.pool == nil || actor == nil || actor.UserID == "" ||
		b.server.requireMFA && !actor.MFASatisfied {
		return nil, apierror.Forbidden("a current authorized tenant user is required")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	check := func(ctx context.Context) error {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return err
		}
		status, err := NewTenantStatusCache(b.server.pool, 0).TenantStatus(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		if status != "active" {
			return apierror.Forbidden("BGP visibility tenant is inactive")
		}
		current, err := loadCurrentUserAuthority(ctx, b.server.pool, actor.TenantID, actor.UserID)
		if err != nil {
			return err
		}
		checked, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		for _, permission := range []string{ai.PermEventsRead, permAIQuery} {
			if err := b.server.authorize(checked, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	if err := check(ctx); err != nil {
		return nil, err
	}
	before, err := bgpVisibilityCutoff(command.Before)
	if err != nil {
		return nil, err
	}
	limit := 100
	if command.Limit != nil {
		limit = *command.Limit
	}
	var out bgpVisibilityHistory
	err = tenancy.InTenantReadSnapshot(ctx, b.server.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = readBGPVisibilityHistory(ctx, sc, command.ID, before, limit)
		return err
	})
	if err != nil {
		return nil, bgpVisibilityAPIError(err)
	}
	if err := mcp.RetainNativePublication(ctx, func(active context.Context) error {
		if err := active.Err(); err != nil {
			return err
		}
		return check(ctx)
	}, func() {}); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func bgpVisibilityCutoff(raw string) (time.Time, error) {
	if raw == "" {
		return time.Now().UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, apierror.Validation("before must be an RFC 3339 timestamp")
	}
	return parsed, nil
}
