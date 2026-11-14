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
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type mcpChangeTimelineBackend struct{ server *Server }

func changeTimelineToolOption(server *Server) (mcp.Option, error) {
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
	for _, parameter := range doc.Paths["/v1/changes"].Get.Parameters {
		if parameter.Name != "" && json.Valid(parameter.Schema) {
			properties[parameter.Name] = parameter.Schema
		}
	}
	if len(properties) != 4 {
		return nil, apierror.Unavailable("change timeline contract is unavailable")
	}
	schema, err := json.Marshal(struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}{Type: "object", Properties: properties})
	if err != nil {
		return nil, err
	}
	return mcp.WithChangeTimelineBackend(mcpChangeTimelineBackend{server}, schema), nil
}

func (b mcpChangeTimelineBackend) ChangeTimeline(ctx context.Context, actor *auth.Principal, command mcp.ChangeTimelineCommand) (json.RawMessage, error) {
	if b.server == nil || actor == nil || actor.UserID == "" {
		return nil, apierror.Forbidden("a current tenant user is required")
	}
	if b.server.pool == nil {
		return nil, apierror.Unavailable("change timeline storage is unavailable")
	}
	if b.server.requireMFA && !actor.MFASatisfied {
		return nil, apierror.Forbidden("multi-factor authentication required")
	}
	var err error
	ctx, err = bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, b.server.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	retained := false
	defer func() {
		if !retained {
			cancel()
		}
	}()
	current, err := loadCurrentUserAuthority(ctx, b.server.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	for _, permission := range []string{permChangeRead, permAIQuery} {
		if err := b.server.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
			return nil, err
		}
	}
	checkTenant := func(ctx context.Context) error {
		status, err := NewTenantStatusCache(b.server.pool, 0).TenantStatus(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		if status != "active" {
			return apierror.Forbidden("change timeline tenant is inactive")
		}
		return ctx.Err()
	}
	if err := checkTenant(ctx); err != nil {
		return nil, err
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	query := url.Values{"cursor": {command.Cursor}, "from": {command.From}, "to": {command.To}}
	if command.Limit != nil {
		query.Set("limit", strconv.Itoa(*command.Limit))
	}
	request, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), http.MethodGet, "/v1/changes?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	scope := newConfigEvidenceScope(b.server, actor, mcp.CheckOriginatingCredential, permChangeRead, permAIQuery)
	body, closeRead, err := b.server.readChangeTimeline(request, scope)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !retained {
			closeRead()
		}
	}()
	body, err = marshalNativeChangeTimeline(body)
	if err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(ctx, func(_ context.Context) error {
		if err := checkTenant(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scope.check(ctx); err != nil {
			return err
		}
		refreshed, err := loadCurrentUserAuthority(ctx, b.server.pool, actor.TenantID, actor.UserID)
		if err != nil {
			return err
		}
		checked, currentActor, err := refreshed.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		for _, permission := range []string{permChangeRead, permAIQuery} {
			if err := b.server.authorize(checked, currentActor, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
				return err
			}
		}
		return mcp.CheckOriginatingCredential(ctx)
	}, func() { closeRead(); cancel() }); err != nil {
		return nil, err
	}
	retained = true
	return body, ctx.Err()
}

// The server-created continuation contains only validated times and a stored
// UUID. Escaping its JSON ASCII prevents PII heuristics rewriting that opaque
// token; it conveys no credential or source authority.
func nativeChangeTimelineCursor(cursor string) (json.RawMessage, error) {
	if cursor == "" {
		return json.RawMessage(`""`), nil
	}
	if _, err := decodeChangeTimelineCursor(cursor); err != nil {
		return nil, err
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, character := range cursor {
		if character > 127 {
			return nil, apierror.Unavailable("invalid generated change cursor")
		}
		out.WriteString(`\u00`)
		const digits = "0123456789abcdef"
		out.WriteByte(digits[byte(character)>>4])
		out.WriteByte(digits[byte(character)&15])
	}
	out.WriteByte('"')
	return json.RawMessage(out.String()), nil
}

func marshalNativeChangeTimeline(body json.RawMessage) (json.RawMessage, error) {
	var result struct {
		Items                  []change.Event `json:"items"`
		ChangeIngestConfigured bool           `json:"change_ingest_configured"`
		ConfigArchiveRunning   bool           `json:"config_archive_running"`
		EffectiveLimit         int            `json:"effective_limit"`
		Truncated              bool           `json:"truncated"`
		NextCursor             string         `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	type event struct {
		change.Event
		ID       json.RawMessage    `json:"id"`
		TenantID mcp.NativeRoleUUID `json:"tenant_id"`
		Routing  json.RawMessage    `json:"routing,omitempty"`
		Config   json.RawMessage    `json:"config,omitempty"`
	}
	output := struct {
		Items                  []event         `json:"items"`
		ChangeIngestConfigured bool            `json:"change_ingest_configured"`
		ConfigArchiveRunning   bool            `json:"config_archive_running"`
		EffectiveLimit         int             `json:"effective_limit"`
		Truncated              bool            `json:"truncated"`
		NextCursor             json.RawMessage `json:"next_cursor"`
	}{Items: []event{}, ChangeIngestConfigured: result.ChangeIngestConfigured, ConfigArchiveRunning: result.ConfigArchiveRunning, EffectiveLimit: result.EffectiveLimit, Truncated: result.Truncated}
	var err error
	output.NextCursor, err = nativeChangeTimelineCursor(result.NextCursor)
	if err != nil {
		return nil, err
	}
	for _, item := range result.Items {
		value := event{Event: item, TenantID: mcp.NativeRoleUUID(item.TenantID)}
		id := item.ID
		prefix := ""
		if strings.HasPrefix(id, "device-config:") {
			prefix = "device-config:"
			id = strings.TrimPrefix(id, prefix)
		}
		encoded, err := json.Marshal(mcp.NativeRoleUUID(id))
		if err != nil {
			return nil, err
		}
		value.ID = append([]byte(`"`+prefix), encoded[1:]...)
		if item.Routing != nil {
			value.Routing, err = nativeRoutingChangeReference(*item.Routing)
			if err != nil {
				return nil, err
			}
		}
		if item.Config != nil {
			value.Config, err = nativeChangeConfigReference(*item.Config)
			if err != nil {
				return nil, err
			}
		}
		output.Items = append(output.Items, value)
	}
	return json.Marshal(output)
}

func nativeChangeConfigReference(reference change.ConfigReference) (json.RawMessage, error) {
	type binding struct {
		*change.ConfigBindingReference
		ContextID      mcp.NativeRoleUUID `json:"context_id"`
		DeviceEntityID mcp.NativeRoleUUID `json:"device_entity_id"`
	}
	var source *binding
	if reference.Binding != nil {
		source = &binding{ConfigBindingReference: reference.Binding, ContextID: mcp.NativeRoleUUID(reference.Binding.ContextID), DeviceEntityID: mcp.NativeRoleUUID(reference.Binding.DeviceEntityID)}
	}
	value := struct {
		CurrentID       mcp.NativeRoleUUID   `json:"current_id"`
		PreviousID      mcp.NativeRoleUUID   `json:"previous_id"`
		CurrentHash     mcp.NativeRoleDigest `json:"current_hash"`
		PreviousHash    mcp.NativeRoleDigest `json:"previous_hash"`
		CurrentVersion  int                  `json:"current_version"`
		PreviousVersion int                  `json:"previous_version"`
		Binding         *binding             `json:"binding,omitempty"`
	}{mcp.NativeRoleUUID(reference.CurrentID), mcp.NativeRoleUUID(reference.PreviousID), mcp.NativeRoleDigest(reference.CurrentHash), mcp.NativeRoleDigest(reference.PreviousHash), reference.CurrentVersion, reference.PreviousVersion, source}
	return json.Marshal(value)
}
