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

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type nativeDeviceConfigPolicyBackend struct{ server *Server }

func deviceConfigPolicyToolOption(server *Server) (mcp.Option, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	roots := make(map[string]any, 3)
	for tool, schema := range map[string]string{
		"device_config_policy":         "DeviceConfigPolicyBindingInput",
		"device_config_policy_publish": "DeviceConfigPolicyPut",
	} {
		var root any
		if err := json.Unmarshal(document.Components.Schemas[schema], &root); err != nil {
			return nil, err
		}
		roots[tool] = root
	}
	input, err := bgpHistoryToolSchema("/v1/device/configs/{id}/policy-evaluation", 2, "id")
	if err != nil {
		return nil, err
	}
	var root any
	if err := json.Unmarshal(input, &root); err != nil {
		return nil, err
	}
	roots["device_config_policy_evaluation"] = root
	schemas, err := nativeMCPInputSchemas(document.Components.Schemas, roots)
	if err != nil {
		return nil, err
	}
	return mcp.WithDeviceConfigPolicyBackend(nativeDeviceConfigPolicyBackend{server}, schemas), nil
}

func (b nativeDeviceConfigPolicyBackend) DeviceConfigPolicy(ctx context.Context, actor *auth.Principal,
	input mcp.DeviceConfigPolicySource) (json.RawMessage, error) {
	binding := configPolicyBindingInput(input).archiveBinding()
	return b.publishRead(ctx, actor, func(ctx context.Context) (json.RawMessage, error) {
		policy, err := b.server.loadDeviceConfigPolicy(ctx, actor, binding)
		if err != nil {
			return nil, configPolicyError(err)
		}
		return json.Marshal(policy)
	})
}

func (b nativeDeviceConfigPolicyBackend) PublishDeviceConfigPolicy(ctx context.Context, actor *auth.Principal,
	input mcp.DeviceConfigPolicyUpdate) (json.RawMessage, error) {
	if err := b.check(ctx, actor); err != nil {
		return nil, err
	}
	if input.Rules == nil {
		return nil, apierror.Validation("supply a rules array, including an empty array to deactivate the policy")
	}
	binding := configPolicyBindingInput(input.Binding).archiveBinding()
	policy, err := b.server.saveDeviceConfigPolicy(ctx, actor, binding, input.ExpectedRevision, input.Rules,
		func(ctx context.Context, sc tenancy.Scope, policy device.ConfigPolicyRevision) error {
			if err := mcp.CheckOriginatingCredential(ctx); err != nil {
				return err
			}
			return audit.TenantRecord(ctx, sc, actor.UserID, "device.config_policy.updated", binding.DeviceEntityID, configPolicyAuditFields(binding, policy))
		})
	if err != nil {
		return nil, configPolicyError(err)
	}
	if err := b.check(ctx, actor); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

func (b nativeDeviceConfigPolicyBackend) DeviceConfigPolicyEvaluation(ctx context.Context, actor *auth.Principal,
	input mcp.DeviceConfigPolicyRead) (json.RawMessage, error) {
	return b.publishRead(ctx, actor, func(ctx context.Context) (json.RawMessage, error) {
		archive, result, err := b.server.loadDeviceConfigPolicyEvaluation(ctx, actor, input.ID)
		if err != nil {
			return nil, configPolicyError(err)
		}
		switch input.Format {
		case "", "json":
			return json.Marshal(map[string]any{"archive_id": mcp.NativeRoleUUID(archive.ID), "observed_at": archive.ObservedAt, "evaluation": result})
		case "csv":
			if result == nil {
				return nil, apierror.NotFound("this archive has no configuration policy evaluation")
			}
			body, err := configPolicyCSV(ctx, result)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"archive_id": mcp.NativeRoleUUID(archive.ID), "content_type": "text/csv", "csv": string(body)})
		default:
			return nil, apierror.BadRequest("format must be json or csv")
		}
	})
}

func (b nativeDeviceConfigPolicyBackend) check(ctx context.Context, actor *auth.Principal) error {
	if b.server == nil || b.server.pool == nil || actor == nil || actor.UserID == "" {
		return apierror.Forbidden("a current authorized tenant user is required")
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return err
	}
	status, err := NewTenantStatusCache(b.server.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return err
	}
	if status != "active" {
		return apierror.Forbidden("configuration policy tenant is inactive")
	}
	return nil
}

func (b nativeDeviceConfigPolicyBackend) publishRead(ctx context.Context, actor *auth.Principal,
	read func(context.Context) (json.RawMessage, error)) (json.RawMessage, error) {
	if err := b.check(ctx, actor); err != nil {
		return nil, err
	}
	body, err := read(ctx)
	if err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(ctx, func(active context.Context) error {
		if err := b.check(active, actor); err != nil {
			return err
		}
		current, err := read(active)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, current) {
			return apierror.Conflict("configuration policy changed before publication")
		}
		return active.Err()
	}, func() {}); err != nil {
		return nil, err
	}
	return body, nil
}
