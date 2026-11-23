// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"

	guuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type configPolicyBindingInput struct {
	ContextID      string `json:"context_id"`
	DeviceEntityID string `json:"device_entity_id"`
	AgentID        string `json:"agent_id"`
	SourceRef      string `json:"source_ref"`
}

func (in configPolicyBindingInput) archiveBinding() device.ConfigArchiveBinding {
	return device.ConfigArchiveBinding{ContextID: in.ContextID, DeviceEntityID: in.DeviceEntityID, AgentID: in.AgentID, SourceRef: in.SourceRef}
}

func (s *Server) handleGetDeviceConfigPolicy(w http.ResponseWriter, r *http.Request) error {
	query := r.URL.Query()
	binding := (configPolicyBindingInput{ContextID: query.Get("context_id"), DeviceEntityID: query.Get("device_entity_id"),
		AgentID: query.Get("agent_id"), SourceRef: query.Get("source_ref")}).archiveBinding()
	if err := s.authorizeConfigArchiveBinding(r, &binding, ai.PermMetricsRead); err != nil {
		return err
	}
	policy, err := s.loadDeviceConfigPolicy(r.Context(), auth.PrincipalFrom(r.Context()), binding)
	if err != nil {
		return configPolicyError(err)
	}
	if err := s.authorizeConfigArchiveBinding(r, &binding, ai.PermMetricsRead); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, policy)
	return nil
}

func (s *Server) loadDeviceConfigPolicy(ctx context.Context, actor *auth.Principal, binding device.ConfigArchiveBinding) (device.ConfigPolicyRevision, error) {
	ctx, err := bindCanonicalDeviceTenant(ctx, actor)
	if err != nil {
		return device.ConfigPolicyRevision{}, err
	}
	var policy device.ConfigPolicyRevision
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := s.authorizeDeviceConfigPolicyInScope(ctx, sc, actor, binding, ai.PermMetricsRead); err != nil {
			return err
		}
		var err error
		policy, err = device.LatestConfigPolicy(ctx, sc, binding)
		return err
	})
	return policy, err
}

func (s *Server) handlePutDeviceConfigPolicy(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Binding          configPolicyBindingInput  `json:"binding"`
		ExpectedRevision string                    `json:"expected_revision"`
		Rules            []device.ConfigPolicyRule `json:"rules"`
	}
	if err := decodeJSONLimit(r, 128<<10, &input); err != nil {
		return err
	}
	if input.Rules == nil {
		return apierror.Validation("supply a rules array, including an empty array to deactivate the policy")
	}
	binding := input.Binding.archiveBinding()
	if err := s.authorizeConfigArchiveBinding(r, &binding, permMetricsWrite); err != nil {
		return err
	}
	policy, err := s.saveDeviceConfigPolicy(r.Context(), auth.PrincipalFrom(r.Context()), binding,
		input.ExpectedRevision, input.Rules, func(ctx context.Context, sc tenancy.Scope, policy device.ConfigPolicyRevision) error {
			return s.recordAudit(ctx, sc, r, "device.config_policy.updated", binding.DeviceEntityID,
				configPolicyAuditFields(binding, policy))
		})
	if err != nil {
		return configPolicyError(err)
	}
	if err := s.authorizeConfigArchiveBinding(r, &binding, permMetricsWrite); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, policy)
	return nil
}

func (s *Server) saveDeviceConfigPolicy(ctx context.Context, actor *auth.Principal, binding device.ConfigArchiveBinding,
	expected string, rules []device.ConfigPolicyRule, record func(context.Context, tenancy.Scope, device.ConfigPolicyRevision) error) (device.ConfigPolicyRevision, error) {
	ctx, err := bindCanonicalDeviceTenant(ctx, actor)
	if err != nil {
		return device.ConfigPolicyRevision{}, err
	}
	var policy device.ConfigPolicyRevision
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := s.authorizeDeviceConfigPolicyInScope(ctx, sc, actor, binding, permMetricsWrite); err != nil {
			return err
		}
		var err error
		policy, err = device.PublishConfigPolicy(ctx, sc, binding, expected, rules)
		if err != nil {
			return err
		}
		return record(ctx, sc, policy)
	})
	return policy, err
}

func configPolicyAuditFields(binding device.ConfigArchiveBinding, policy device.ConfigPolicyRevision) map[string]any {
	return map[string]any{"context_id": binding.ContextID, "policy_version": policy.Version, "rules": len(policy.Rules)}
}

func (s *Server) readDeviceConfigPolicyEvaluation(r *http.Request) (device.ConfigVersion, *device.ConfigPolicyEvaluation, error) {
	if s.pool == nil {
		return device.ConfigVersion{}, nil, apierror.Unavailable("configuration policy evidence is unavailable")
	}
	archive, evaluation, err := s.loadDeviceConfigPolicyEvaluation(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return device.ConfigVersion{}, nil, configPolicyError(err)
	}
	if err := s.authorizeConfigArchiveBinding(r, archive.Binding, ai.PermMetricsRead); err != nil {
		return device.ConfigVersion{}, nil, err
	}
	return archive, evaluation, nil
}

func (s *Server) loadDeviceConfigPolicyEvaluation(ctx context.Context, actor *auth.Principal, original string) (device.ConfigVersion, *device.ConfigPolicyEvaluation, error) {
	id, err := guuid.Parse(original)
	if err != nil || id == guuid.Nil || id.String() != original {
		return device.ConfigVersion{}, nil, apierror.BadRequest("invalid configuration archive ID")
	}
	ctx, err = bindCanonicalDeviceTenant(ctx, actor)
	if err != nil {
		return device.ConfigVersion{}, nil, err
	}
	var archive device.ConfigVersion
	var evaluation *device.ConfigPolicyEvaluation
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		archive, evaluation, err = device.ReadConfigPolicyEvaluation(ctx, sc, id.String())
		if err != nil {
			return err
		}
		if archive.Binding == nil {
			return pgx.ErrNoRows
		}
		return s.authorizeDeviceConfigPolicyInScope(ctx, sc, actor, *archive.Binding, ai.PermMetricsRead)
	})
	return archive, evaluation, err
}

func bindCanonicalDeviceTenant(ctx context.Context, actor *auth.Principal) (context.Context, error) {
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, tenancy.ErrNoTenant
	}
	current, ok := tenancy.FromContext(ctx)
	if ok && current.String() != actor.TenantID {
		return nil, tenancy.ErrNoTenant
	}
	return tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID)), nil
}

func (s *Server) authorizeDeviceConfigPolicyInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal,
	binding device.ConfigArchiveBinding, permission string) error {
	source := entity.SourceKey{AgentID: binding.AgentID, Kind: entity.DeviceTarget, SourceRef: binding.SourceRef}
	return s.authorizeCanonicalDeviceSourceInScope(ctx, sc, actor, binding.ContextID, binding.DeviceEntityID, source, permission)
}

func (s *Server) authorizeCanonicalDeviceSourceInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal,
	contextID, deviceID string, source entity.SourceKey, permission string) error {
	if actor == nil || actor.TenantID != sc.Tenant.String() {
		return tenancy.ErrNoTenant
	}
	scope, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, contextID)
	if err != nil {
		return entityAPIError(err)
	}
	resource := entityContextResource(scope)
	resource["entity_id"], resource["agent_id"], resource["source_kind"], resource["source_ref"] =
		deviceID, source.AgentID, string(source.Kind), source.SourceRef
	authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := authority.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	for _, required := range []string{permission, ai.PermEntitiesRead} {
		if err := s.authorize(ctx, principal, required, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return nil
}

func configPolicyError(err error) error {
	var apiErr *apierror.Error
	switch {
	case errors.As(err, &apiErr):
		return apiErr
	case errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("the owned configuration archive or current device source is unavailable")
	case errors.Is(err, device.ErrConfigPolicyChanged):
		return apierror.Conflict("the policy was revised, reload it before publishing")
	case errors.Is(err, device.ErrConfigBinding), errors.Is(err, device.ErrConfigPolicyRules):
		return apierror.Validation("the device policy or original archive is invalid")
	default:
		return apierror.Unavailable("device configuration policy is temporarily unavailable")
	}
}
