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

	"github.com/ctlplne/probectl/internal/ai"
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

func (b mcpPathHealthBackend) ExplainPathInterfaceHealth(ctx context.Context, actor *auth.Principal, input mcp.PathHealthExplanationCommand) (json.RawMessage, error) {
	if b.server == nil || b.server.analyzer == nil || actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, apierror.Forbidden("a current tenant user and path analyzer are required")
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), http.MethodPost, "/v1/ai/ask", nil)
	if err != nil {
		return nil, err
	}
	subject := map[string]string{"path_test_id": input.TestID, "health_from": input.HealthFrom, "health_to": input.HealthTo, "health_poll_gap": input.HealthPollGap, "health_max_bps": input.HealthMaxBPS}
	analysisCtx, prepared, err := b.server.preparePathHealthRCA(request, subject, ai.TimeRange{}, mcp.CheckOriginatingCredential)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			prepared.query.op.done()
		}
	}()
	answer, err := b.server.analyzer.Analyze(analysisCtx, actor, ai.Question{Text: input.Question, Subject: subject})
	if err != nil {
		return nil, err
	}
	body, err := marshalNativePathHealthAnswer(answer)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > prepared.query.op.budget.ResponseBytes || int64(len(body)) > prepared.query.remaining {
		return nil, apierror.TooLarge("complete native path explanation exceeds response admission")
	}
	if err := mcp.RetainNativePublication(ctx, func(ctx context.Context) error {
		return b.server.checkPathHealthRCA(ctx, prepared)
	}, prepared.query.op.done); err != nil {
		return nil, err
	}
	retained = true
	return body, analysisCtx.Err()
}

func marshalNativePathHealthAnswer(answer ai.Answer) (json.RawMessage, error) {
	type evidence struct {
		ai.Evidence
		Fields ai.Row          `json:"fields,omitempty"`
		Ref    json.RawMessage `json:"ref,omitempty"`
	}
	type step struct {
		ai.InvestigationStep
		Selector map[string]any `json:"selector,omitempty"`
	}
	native := struct {
		ai.Answer
		Tenant            mcp.NativeRoleUUID `json:"tenant"`
		Evidence          []evidence         `json:"evidence"`
		InvestigationPlan []step             `json:"investigation_plan,omitempty"`
	}{Answer: answer, Tenant: mcp.NativeRoleUUID(answer.Tenant), Evidence: make([]evidence, 0, len(answer.Evidence))}
	for _, item := range answer.Evidence {
		fields := make(ai.Row, len(item.Fields))
		for key, value := range item.Fields {
			fields[key] = value
		}
		id, ok := fields["path_test_id"].(string)
		if !ok || item.Ref != "/path?test_id="+id {
			return nil, apierror.Unavailable("path explanation lost its owned source reference")
		}
		encodedID, err := json.Marshal(mcp.NativeRoleUUID(id))
		if err != nil {
			return nil, err
		}
		fields["path_test_id"] = mcp.NativeRoleUUID(id)
		ref := append([]byte(`"/path?test_id=`), encodedID[1:]...)
		native.Evidence = append(native.Evidence, evidence{Evidence: item, Fields: fields, Ref: ref})
	}
	for _, item := range answer.InvestigationPlan {
		selector := make(map[string]any, len(item.Selector))
		for key, value := range item.Selector {
			if key == "path_test_id" {
				selector[key] = mcp.NativeRoleUUID(value)
			} else {
				selector[key] = value
			}
		}
		native.InvestigationPlan = append(native.InvestigationPlan, step{InvestigationStep: item, Selector: selector})
	}
	return json.Marshal(native)
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
