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

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type interfaceRolePolicyInput struct {
	ExpectedID       string                                `json:"expected_id"`
	ExpectedRevision string                                `json:"expected_revision"`
	Definition       *entity.InterfaceRolePolicyDefinition `json:"definition"`
}

type interfaceRoleOverrideInput struct {
	ExpectedID       string               `json:"expected_id"`
	ExpectedRevision string               `json:"expected_revision"`
	Role             entity.InterfaceRole `json:"role"`
}

type interfaceRoleResetInput struct {
	ExpectedID       string `json:"expected_id"`
	ExpectedRevision string `json:"expected_revision"`
	Confirmed        bool   `json:"confirmed"`
}

func (s *Server) interfaceRoleRoutes() []apiRoute {
	return []apiRoute{
		{http.MethodGet, "/v1/entity-contexts/{context_id}/interfaces/{id}/role", s.handleInterfaceRoleExplanation, ai.PermEntitiesRead},
		{http.MethodGet, "/v1/entity-contexts/{context_id}/interface-role-policy", s.handleInterfaceRolePolicy, ai.PermEntitiesRead},
		{http.MethodPut, "/v1/entity-contexts/{context_id}/interface-role-policy", s.handleInterfaceRolePolicy, permAgentWrite},
		{http.MethodGet, "/v1/entity-contexts/{context_id}/interfaces/{id}/role-override", s.handleInterfaceRoleOverride, ai.PermEntitiesRead},
		{http.MethodPut, "/v1/entity-contexts/{context_id}/interfaces/{id}/role-override", s.handleInterfaceRoleOverride, permAgentWrite},
		{http.MethodDelete, "/v1/entity-contexts/{context_id}/interfaces/{id}/role-override", s.handleInterfaceRoleOverride, permAgentWrite},
	}
}

// REST and native tools share this admission. Context authorization resolves
// the current context under tenant RLS before configuration SQL. Operator
// configuration does not grant a source read or fabricate source freshness.
func (s *Server) beginInterfaceRoleOperation(r *http.Request) (*http.Request, flowstore.ExplorerBudget, func(), error) {
	p := auth.PrincipalFrom(r.Context())
	if p == nil || p.TenantID == "" {
		return nil, flowstore.ExplorerBudget{}, nil, apierror.Unauthorized("tenant identity is required")
	}
	if err := s.checkTenantLifecycle(r, p.TenantID); err != nil {
		return nil, flowstore.ExplorerBudget{}, nil, err
	}
	if s.requireMFA && !p.MFASatisfied {
		return nil, flowstore.ExplorerBudget{}, nil, apierror.Forbidden("multi-factor authentication required")
	}
	permission := ai.PermEntitiesRead
	if r.Method != http.MethodGet {
		permission = permAgentWrite
	}
	if err := s.authorize(r.Context(), p, permission, auth.RBACGlobal, nil); err != nil {
		return nil, flowstore.ExplorerBudget{}, nil, err
	}
	if s.pool == nil {
		return nil, flowstore.ExplorerBudget{}, nil, apierror.Unavailable("interface role configuration store is unavailable")
	}
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if budget.Validate() != nil {
		return nil, budget, nil, apierror.Unavailable("interface role operation admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenancy.ID(p.TenantID)), budget.ExecutionLimit)
	r = r.WithContext(ctx)
	if _, err := s.authorizeTagContext(r, r.PathValue("context_id"), permission); err != nil {
		cancel()
		return nil, budget, nil, err
	}
	if s.fairnessGate != nil {
		done, err := s.fairnessGate.BeginQuery(ctx, p.TenantID)
		if err != nil {
			cancel()
			return nil, budget, nil, tagQueryAdmissionError(err)
		}
		return r, budget, func() { done(); cancel() }, nil
	}
	return r, budget, cancel, nil
}

// Reserve a quarter for decoded request memory; the store divides the rest
// across current state, normalization and encoding. No logical rule/count cap.
func interfaceRoleStoreBudget(b flowstore.ExplorerBudget) entity.InterfaceRolePolicyBudget {
	return entity.InterfaceRolePolicyBudget{MemoryBytes: b.MemoryBytes - b.MemoryBytes/4, WorkUnits: b.MemoryBytes / 2}
}

func interfaceRoleBodyBytes(b flowstore.ExplorerBudget) int64 {
	return min(b.ResponseBytes, b.MemoryBytes/16)
}

// Multi-statement configuration/audit transactions retain the existing silo
// relation locks from entry through commit, including not-yet-read tables. A
// concurrent DROP must never redirect a later statement to pooled public data.
//
// Encode before the audit/transaction commits. A complete response that cannot
// fit the positive operator profile rolls the entire write back, never leaves
// a successful mutation followed by a response-budget error.
func interfaceRolePublication(value any, budget flowstore.ExplorerBudget) (json.RawMessage, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > min(budget.ResponseBytes, budget.MemoryBytes/4) {
		return nil, entity.ErrInterfaceRoleBudget
	}
	return body, nil
}

func (s *Server) handleInterfaceRolePolicy(w http.ResponseWriter, r *http.Request) error {
	body, err := s.interfaceRolePolicy(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

func (s *Server) interfaceRolePolicy(r *http.Request) (json.RawMessage, error) {
	r, budget, done, err := s.beginInterfaceRoleOperation(r)
	if err != nil {
		return nil, err
	}
	defer done()
	var input interfaceRolePolicyInput
	if r.Method == http.MethodPut {
		if err := decodeJSONLimit(r, interfaceRoleBodyBytes(budget), &input); err != nil {
			return nil, err
		}
		if input.Definition == nil {
			return nil, apierror.BadRequest("complete policy definition is required")
		}
	}
	var body json.RawMessage
	err = s.inTenant(r.WithContext(tenancy.WithSiloTableLock(r.Context())), func(ctx context.Context, sc tenancy.Scope) error {
		var out entity.InterfaceRolePolicyRecord
		var err error
		contextID := r.PathValue("context_id")
		configuration := store.InterfaceRoleConfiguration{}
		if r.Method == http.MethodPut {
			out, err = configuration.PutPolicy(ctx, sc, contextID, input.ExpectedID, input.ExpectedRevision, *input.Definition, interfaceRoleStoreBudget(budget))
		} else {
			out, err = configuration.Policy(ctx, sc, contextID, interfaceRoleStoreBudget(budget))
		}
		if err != nil {
			return err
		}
		body, err = interfaceRolePublication(out, budget)
		if err != nil || r.Method == http.MethodGet {
			return err
		}
		// Audit stable configuration/version and cardinality, never regex or
		// tenant declarations copied into a second retained subject surface.
		return s.recordAudit(ctx, sc, r, "interface.role.policy.updated", out.ID, map[string]any{
			"context_id": contextID, "revision": out.Revision,
			"provider_count": len(out.Definition.ProviderASNs), "customer_count": len(out.Definition.CustomerASNs),
			"description_rule_count": len(out.Definition.DescriptionRules),
		})
	})
	return body, interfaceRoleAPIError(err)
}

func (s *Server) handleInterfaceRoleOverride(w http.ResponseWriter, r *http.Request) error {
	body, err := s.interfaceRoleOverride(r)
	if err != nil {
		return err
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
	} else {
		writeJSON(w, http.StatusOK, body)
	}
	return nil
}

func (s *Server) interfaceRoleOverride(r *http.Request) (json.RawMessage, error) {
	r, budget, done, err := s.beginInterfaceRoleOperation(r)
	if err != nil {
		return nil, err
	}
	defer done()
	var input interfaceRoleOverrideInput
	var reset interfaceRoleResetInput
	switch r.Method {
	case http.MethodPut:
		if err := decodeJSONLimit(r, interfaceRoleBodyBytes(budget), &input); err != nil {
			return nil, err
		}
	case http.MethodDelete:
		if err := decodeJSONLimit(r, interfaceRoleBodyBytes(budget), &reset); err != nil {
			return nil, err
		}
		if !reset.Confirmed {
			return nil, apierror.BadRequest("explicit override reset confirmation is required")
		}
	}
	var body json.RawMessage
	err = s.inTenant(r.WithContext(tenancy.WithSiloTableLock(r.Context())), func(ctx context.Context, sc tenancy.Scope) error {
		var out entity.InterfaceRoleOverrideRecord
		var err error
		contextID, interfaceID := r.PathValue("context_id"), r.PathValue("id")
		configuration := store.InterfaceRoleConfiguration{}
		switch r.Method {
		case http.MethodPut:
			out, err = configuration.PutOverride(ctx, sc, contextID, interfaceID, input.ExpectedID, input.ExpectedRevision, input.Role)
		case http.MethodDelete:
			err = configuration.ResetOverride(ctx, sc, contextID, interfaceID, reset.ExpectedID, reset.ExpectedRevision)
			out = entity.InterfaceRoleOverrideRecord{ID: reset.ExpectedID, Revision: reset.ExpectedRevision}
		default:
			out, err = configuration.Override(ctx, sc, contextID, interfaceID)
		}
		if err != nil {
			return err
		}
		body, err = interfaceRolePublication(out, budget)
		if err != nil || r.Method == http.MethodGet {
			return err
		}
		action := "interface.role.override.updated"
		if r.Method == http.MethodDelete {
			action = "interface.role.override.reset"
		}
		return s.recordAudit(ctx, sc, r, action, out.ID, map[string]any{
			"context_id": contextID, "interface_id": interfaceID, "revision": out.Revision, "role": out.Role,
		})
	})
	return body, interfaceRoleAPIError(err)
}

func interfaceRoleAPIError(err error) error {
	switch {
	case errors.Is(err, entity.ErrInterfaceRolePolicy):
		return apierror.BadRequest("invalid interface role configuration")
	case errors.Is(err, entity.ErrInterfaceRoleConflict):
		return apierror.Conflict("interface role configuration changed; reload before editing")
	case errors.Is(err, entity.ErrInterfaceRoleBudget), errors.Is(err, errInterfaceRoleBudget):
		return apierror.RateLimited("complete interface role configuration exceeds operation admission")
	case errors.Is(err, errInterfaceRoleInput):
		return apierror.Unavailable("current interface role evidence is unavailable")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return apierror.Unavailable("interface role operation was canceled or exceeded its execution budget")
	default:
		return entityAdminError(err)
	}
}
