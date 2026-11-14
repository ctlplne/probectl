// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type mcpChangeEffectsBackend struct{ server *Server }

func changeEffectsToolOption(server *Server) (mcp.Option, error) {
	var document struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string          `json:"name"`
					Schema json.RawMessage `json:"schema"`
				} `json:"parameters"`
			} `json:"get"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	properties := map[string]json.RawMessage{}
	for _, parameter := range document.Paths["/v1/changes/{id}/effects"].Get.Parameters {
		name := parameter.Name
		if name == "id" {
			name = "change_id"
		}
		if name != "" && json.Valid(parameter.Schema) {
			properties[name] = parameter.Schema
		}
	}
	if len(properties) != 4 {
		return nil, apierror.Unavailable("change effect contract is unavailable")
	}
	schema, err := json.Marshal(struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}{Type: "object", Properties: properties, Required: []string{"change_id", "from", "to"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithChangeEffectsBackend(mcpChangeEffectsBackend{server}, schema), nil
}

func (b mcpChangeEffectsBackend) ChangeEffects(ctx context.Context, actor *auth.Principal, command mcp.ChangeEffectsCommand) (json.RawMessage, error) {
	if b.server == nil || actor == nil || actor.UserID == "" {
		return nil, apierror.Forbidden("a current tenant user is required")
	}
	if b.server.pool == nil {
		return nil, apierror.Unavailable("change effect storage is unavailable")
	}
	if b.server.requireMFA && !actor.MFASatisfied {
		return nil, apierror.Forbidden("multi-factor authentication required")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
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
	checkNative := func(ctx context.Context) error {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return err
		}
		current, err := loadCurrentUserAuthority(ctx, b.server.pool, actor.TenantID, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		return b.server.authorize(ctx, principal, permAIQuery, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID})
	}
	if err := checkNative(ctx); err != nil {
		return nil, err
	}
	scope := newConfigEvidenceScope(b.server, actor, checkNative, permChangeRead, permFlowRead, permTestRead, "events.read", permAIQuery)
	result, publication, err := b.server.computeChangeEffects(ctx, scope, command.ChangeID, changeEffectsInput{From: command.From, To: command.To, DataSeries: command.DataSeries})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !retained {
			publication.close()
		}
	}()
	body, err := marshalNativeChangeEffects(result)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > budget.ResponseBytes {
		return nil, flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	if err := mcp.RetainNativePublication(ctx, publication.check, func() { publication.close(); cancel() }); err != nil {
		return nil, err
	}
	retained = true
	return body, ctx.Err()
}
