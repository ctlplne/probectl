// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type mcpCapacityAgreementBackend struct{ server *Server }

func (b mcpCapacityAgreementBackend) CapacityAgreements(ctx context.Context, p *auth.Principal, name string, input mcp.CapacityAgreementCommand) (json.RawMessage, error) {
	if b.server == nil || p == nil || p.UserID == "" || p.TenantID == "" {
		return nil, apierror.Forbidden("current tenant financial user is required")
	}
	ctx, err := bindFlowRoleContext(ctx, p)
	if err != nil {
		return nil, err
	}
	if name == "capacity_agreement_bill_check" {
		return b.capacityAgreementBill(ctx, input)
	}
	method := http.MethodGet
	switch name {
	case "capacity_agreements_list", "capacity_agreement_get", "capacity_agreement_revisions":
	case "capacity_agreement_create":
		method = http.MethodPost
	case "capacity_agreement_update":
		method = http.MethodPut
	case "capacity_agreement_delete":
		method = http.MethodDelete
	default:
		return nil, apierror.BadRequest("unknown financial command")
	}
	write := method != http.MethodGet
	if write && b.server.cluster != nil {
		if usable, _ := b.server.cluster.WriterUsableNow(ctx); !usable {
			return nil, apierror.Unavailable("writer unavailable")
		}
	}
	// Reuse the same operation boundary, not an HTTP round trip or an unchecked
	// store: current user/credential/ABAC, tenant status, fairness, deadline,
	// FORCE-RLS snapshot authorization and lifecycle-fenced mutation all apply.
	request, err := http.NewRequestWithContext(ctx, method, "/v1/flows/capacity/agreements", nil)
	if err != nil {
		return nil, err
	}
	op, err := b.server.beginCapacityAgreement(request)
	if err != nil {
		return nil, capacityAgreementAPIError(err)
	}
	defer op.done()
	ctx = op.request.Context()
	var item flow.CapacityAgreement
	var page flow.CapacityAgreementPage
	limit := 0
	if input.Limit != nil {
		limit = *input.Limit
	}
	switch name {
	case "capacity_agreements_list":
		page, err = op.store.ListCapacityAgreements(ctx, p.UserID, flow.CapacityAgreementList{After: input.After, Limit: limit})
	case "capacity_agreement_revisions":
		page, err = op.store.ListCapacityAgreementRevisions(ctx, p.UserID, input.ID, flow.CapacityAgreementList{After: input.After, Limit: limit})
	case "capacity_agreement_get":
		if input.At != "" && input.Version != "" {
			return nil, apierror.Validation("choose an exact revision or effective instant")
		}
		if input.At == "" {
			item, err = op.store.GetCapacityAgreement(ctx, p.UserID, input.ID, input.Version)
		} else {
			var at time.Time
			at, err = time.Parse(time.RFC3339Nano, input.At)
			if err != nil {
				return nil, apierror.Validation("an RFC3339 effective instant is required")
			}
			item, err = op.store.CapacityAgreementAt(ctx, p.UserID, input.ID, at)
		}
	case "capacity_agreement_create", "capacity_agreement_update":
		if input.Definition == nil || name == "capacity_agreement_create" && (input.ID != "" || input.Version != "") || name == "capacity_agreement_update" && input.ID == "" {
			return nil, apierror.Validation("complete financial terms and the observed head for an update are required")
		}
		item, err = op.store.SaveCapacityAgreement(ctx, p.UserID, flow.SaveCapacityAgreement{ID: input.ID, Version: input.Version, Definition: *input.Definition})
	case "capacity_agreement_delete":
		err = op.store.DeleteCapacityAgreement(ctx, p.UserID, input.ID, input.Version)
	}
	if err != nil {
		return nil, capacityAgreementAPIError(err)
	}
	if err := b.server.currentCapacityAgreementActor(ctx, p, write); err != nil {
		return nil, capacityAgreementAPIError(err)
	}
	if name == "capacity_agreements_list" || name == "capacity_agreement_revisions" {
		return marshalCapacityAgreementPage(page, name == "capacity_agreement_revisions")
	}
	if name == "capacity_agreement_delete" {
		return json.RawMessage(`{"deleted":true}`), nil
	}
	return json.Marshal(nativeCapacityAgreement(item))
}

type nativeCapacityAgreementValue struct {
	flow.CapacityAgreement
	ID             mcp.NativeRoleUUID     `json:"id"`
	Version        mcp.NativeRoleRevision `json:"version"`
	CurrentVersion mcp.NativeRoleRevision `json:"current_version"`
	Definition     any                    `json:"definition"`
}

type nativeCapacityTarget struct {
	flow.CapacityTarget
	ContextID   mcp.NativeRoleUUID `json:"context_id,omitempty"`
	InterfaceID mcp.NativeRoleUUID `json:"interface_id,omitempty"`
	TagID       mcp.NativeRoleUUID `json:"tag_id,omitempty"`
}
type nativeCapacityDefinition struct {
	flow.CapacityAgreementDefinition
	Target nativeCapacityTarget `json:"target"`
}

func nativeCapacityAgreement(item flow.CapacityAgreement) nativeCapacityAgreementValue {
	// Current normalized target FKs prove canonical UUID metadata. Retired
	// references do not confer that current proof. Operator-entered names,
	// references, tag values and prices always traverse full PII redaction.
	var definition any = item.Definition
	if item.TargetPresent {
		target := item.Definition.Target
		definition = nativeCapacityDefinition{item.Definition, nativeCapacityTarget{target, mcp.NativeRoleUUID(target.ContextID), mcp.NativeRoleUUID(target.InterfaceID), mcp.NativeRoleUUID(target.TagID)}}
	}
	return nativeCapacityAgreementValue{item, mcp.NativeRoleUUID(item.ID), mcp.NativeRoleRevision(item.Version), mcp.NativeRoleRevision(item.CurrentVersion), definition}
}

func marshalCapacityAgreementPage(page flow.CapacityAgreementPage, revisions bool) (json.RawMessage, error) {
	result := struct {
		Items   []nativeCapacityAgreementValue `json:"items"`
		Next    any                            `json:"next,omitempty"`
		HasMore bool                           `json:"has_more"`
		AsOf    time.Time                      `json:"as_of"`
	}{Items: make([]nativeCapacityAgreementValue, 0, len(page.Items)), HasMore: page.HasMore, AsOf: page.AsOf}
	for _, item := range page.Items {
		result.Items = append(result.Items, nativeCapacityAgreement(item))
	}
	if page.Next != "" {
		if revisions {
			result.Next = mcp.NativeRoleRevision(page.Next)
		} else {
			result.Next = mcp.NativeRoleUUID(page.Next)
		}
	}
	return json.Marshal(result)
}

func capacityAgreementToolOption(server *Server) (mcp.Option, error) {
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		return nil, err
	}
	roots := map[string]any{}
	for _, name := range []string{"capacity_agreements_list", "capacity_agreement_get", "capacity_agreement_revisions", "capacity_agreement_create", "capacity_agreement_update", "capacity_agreement_delete", "capacity_agreement_bill_check"} {
		properties := map[string]any{}
		required := []string{}
		if name != "capacity_agreements_list" && name != "capacity_agreement_create" {
			properties["id"] = map[string]any{"type": "string", "format": "uuid"}
			required = append(required, "id")
		}
		switch name {
		case "capacity_agreements_list", "capacity_agreement_revisions":
			properties["after"] = map[string]any{"type": "string"}
			properties["limit"] = map[string]any{"type": "integer", "minimum": 1}
		case "capacity_agreement_bill_check":
			properties["check"] = map[string]any{"$ref": "#/components/schemas/CapacityBillInput"}
			required = append(required, "check")
		case "capacity_agreement_get":
			properties["version"] = map[string]any{"type": "string", "pattern": "^[1-9][0-9]*$"}
			properties["at"] = map[string]any{"type": "string", "format": "date-time"}
		case "capacity_agreement_create", "capacity_agreement_update":
			properties["definition"] = map[string]any{"$ref": "#/components/schemas/CapacityAgreementDefinition"}
			required = append(required, "definition")
		}
		if name == "capacity_agreement_update" || name == "capacity_agreement_delete" {
			properties["version"] = map[string]any{"type": "string", "pattern": "^[1-9][0-9]*$"}
			required = append(required, "version")
		}
		roots[name] = map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
	}
	schemas, err := nativeMCPInputSchemas(doc.Components.Schemas, roots)
	if err != nil {
		return nil, err
	}
	budget := flowstore.ExplorerQueryBudget(server.flowStore)
	if budget.Validate() != nil {
		return nil, errors.New("financial operation admission is unavailable")
	}
	return mcp.WithCapacityAgreementBackend(mcpCapacityAgreementBackend{server}, schemas, int(budget.MemoryBytes/64)), nil
}
