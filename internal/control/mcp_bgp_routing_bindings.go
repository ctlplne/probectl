// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type mcpBGPRoutingBindingBackend struct{ server *Server }

func (b mcpBGPRoutingBindingBackend) BGPRoutingBindings(ctx context.Context, actor *auth.Principal, write bool, input mcp.BGPRoutingBindingCommand) (json.RawMessage, error) {
	if b.server == nil || actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, apierror.Unauthorized("tenant user identity is required")
	}
	path := "/v1/entity-contexts/" + url.PathEscape(input.ContextID) + "/bgp-routing-bindings"
	method := http.MethodGet
	var body []byte
	var err error
	if write {
		method = http.MethodPut
		body, err = json.Marshal(struct {
			CollectorAgentID string           `json:"collector_agent_id"`
			SourceRef        string           `json:"source_ref"`
			ExpectedEpoch    *string          `json:"expected_epoch"`
			Bindings         *json.RawMessage `json:"bindings"`
		}{input.CollectorAgentID, input.SourceRef, input.ExpectedEpoch, input.Bindings})
		if err != nil {
			return nil, err
		}
		if b.server.cluster != nil {
			if ok, _ := b.server.cluster.WriterUsableNow(ctx); !ok {
				return nil, apierror.Unavailable("writer unavailable")
			}
		}
	} else {
		path += "?" + url.Values{"collector_agent_id": {input.CollectorAgentID}, "source_ref": {input.SourceRef}}.Encode()
	}
	r, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), method, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("context_id", input.ContextID)
	raw, err := b.server.bgpRoutingBindings(r)
	if err != nil {
		return nil, err
	}
	return marshalBGPRoutingMCPConfiguration(raw)
}

func bgpRoutingBindingToolOption(s *Server) (mcp.Option, error) {
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		return nil, err
	}
	var replacement map[string]any
	if err := json.Unmarshal(doc.Components.Schemas["BGPRoutingBindingReplacement"], &replacement); err != nil {
		return nil, err
	}
	properties, ok := replacement["properties"].(map[string]any)
	if !ok {
		return nil, errors.New("routing binding input schema unavailable")
	}
	properties["context_id"] = map[string]any{"type": "string", "format": "uuid"}
	replacement["required"] = append(replacement["required"].([]any), "context_id")
	read := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"context_id", "collector_agent_id", "source_ref"}, "properties": map[string]any{
		"context_id": properties["context_id"], "collector_agent_id": properties["collector_agent_id"], "source_ref": properties["source_ref"],
	}}
	schemas, err := nativeMCPInputSchemas(doc.Components.Schemas, map[string]any{"bgp_routing_bindings": read, "bgp_routing_bindings_replace": replacement})
	if err != nil {
		return nil, err
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if budget.Validate() != nil {
		return nil, errors.New("routing binding operation admission unavailable")
	}
	return mcp.WithBGPRoutingBindingBackend(mcpBGPRoutingBindingBackend{s}, schemas, int(interfaceRoleBodyBytes(budget))), nil
}

type bgpMCPBinding struct {
	ID            mcp.NativeRoleUUID `json:"id"`
	ContextID     mcp.NativeRoleUUID `json:"context_id"`
	RouterID      mcp.NativeRoleUUID `json:"router_id"`
	Distinguisher string             `json:"distinguisher"`
	BGPIdentifier string             `json:"bgp_identifier"`
	Families      []uint16           `json:"families"`
	SourceFormat  string             `json:"source_format,omitempty"`
}

type bgpMCPBindingManifest struct {
	Epoch      mcp.NativeRoleUUID `json:"epoch"`
	AssignedAt time.Time          `json:"assigned_at"`
	Bindings   []bgpMCPBinding    `json:"bindings"`
}

// Only canonical stored/server-generated UUIDs get structural encoding.
// Sender identities and protocol/operator values keep full egress redaction.
func marshalBGPRoutingMCPConfiguration(raw json.RawMessage) (json.RawMessage, error) {
	var input store.BGPRoutingBindingConfiguration
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, err
	}
	var manifest *bgpMCPBindingManifest
	if input.Manifest != nil {
		manifest = &bgpMCPBindingManifest{Epoch: mcp.NativeRoleUUID(input.Manifest.Epoch), AssignedAt: input.Manifest.AssignedAt, Bindings: make([]bgpMCPBinding, 0, len(input.Manifest.Bindings))}
		for _, binding := range input.Manifest.Bindings {
			manifest.Bindings = append(manifest.Bindings, bgpMCPBinding{mcp.NativeRoleUUID(binding.ID), mcp.NativeRoleUUID(binding.ContextID), mcp.NativeRoleUUID(binding.RouterID), binding.Distinguisher, binding.BGPIdentifier, binding.Families, binding.SourceFormat})
		}
	}
	return json.Marshal(struct {
		CollectorAgentID string                 `json:"collector_agent_id"`
		SourceRef        string                 `json:"source_ref"`
		ContextID        mcp.NativeRoleUUID     `json:"context_id"`
		RouterID         mcp.NativeRoleUUID     `json:"router_id"`
		Manifest         *bgpMCPBindingManifest `json:"manifest"`
	}{input.CollectorAgentID, input.SourceRef, mcp.NativeRoleUUID(input.ContextID), mcp.NativeRoleUUID(input.RouterID), manifest})
}
