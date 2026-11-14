// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

type mcpPathHealthBackend struct{ server *Server }

func pathHealthToolOption(server *Server) (mcp.Option, error) {
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
	properties := map[string]json.RawMessage{"test_id": json.RawMessage(`{"type":"string","format":"uuid"}`)}
	for _, parameter := range doc.Paths["/v1/tests/{id}/path/entities"].Get.Parameters {
		if strings.HasPrefix(parameter.Name, "health_") && json.Valid(parameter.Schema) {
			properties[parameter.Name] = parameter.Schema
		}
	}
	if len(properties) != 5 {
		return nil, apierror.Internal("path health parameter contract is unavailable")
	}
	schema, err := json.Marshal(struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}{Type: "object", Properties: properties, Required: []string{"test_id"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithPathHealthBackend(mcpPathHealthBackend{server}, schema), nil
}

func (b mcpPathHealthBackend) PathInterfaceHealth(ctx context.Context, actor *auth.Principal, input mcp.PathHealthCommand) (json.RawMessage, error) {
	if b.server == nil || actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, apierror.Forbidden("a current tenant user is required")
	}
	values := url.Values{}
	for key, value := range map[string]string{"health_from": input.HealthFrom, "health_to": input.HealthTo, "health_poll_gap": input.HealthPollGap, "health_max_bps": input.HealthMaxBPS} {
		if value != "" {
			values.Set(key, value)
		}
	}
	request, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), http.MethodGet, "/v1/tests/"+url.PathEscape(input.TestID)+"/path/entities?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.SetPathValue("id", input.TestID)
	query, err := b.server.beginPathHealth(request)
	if err != nil {
		return nil, pathHealthError(err)
	}
	retained := false
	defer func() {
		if !retained {
			query.op.done()
		}
	}()
	snapshot, err := b.server.readPathHealth(query)
	if err != nil {
		return nil, pathHealthError(err)
	}
	body, err := marshalNativePathHealth(snapshot.result)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > query.op.budget.ResponseBytes || int64(len(body)) > query.op.budget.MemoryBytes/2 {
		return nil, apierror.TooLarge("complete native path health exceeds response admission")
	}
	if err := mcp.RetainNativePublication(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return b.server.revalidatePathHealthSnapshot(query, snapshot)
	}, query.op.done); err != nil {
		return nil, err
	}
	retained = true
	// The native server refreshes the exact originating HTTPS/stdio credential
	// after this complete projection has traversed mandatory full redaction.
	return body, query.op.request.Context().Err()
}
