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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type bgpRoutingBindingsInput struct {
	CollectorAgentID string                     `json:"collector_agent_id"`
	SourceRef        string                     `json:"source_ref"`
	ExpectedEpoch    *string                    `json:"expected_epoch"`
	Bindings         *[]store.BGPRoutingBinding `json:"bindings"`
}

func (s *Server) handleBGPRoutingBindings(w http.ResponseWriter, r *http.Request) error {
	body, err := s.bgpRoutingBindings(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

// REST and native adapters share admission, current actor/credential authority,
// stored context policy checks, complete publication and the same audit write.
func (s *Server) bgpRoutingBindings(r *http.Request) (json.RawMessage, error) {
	r, budget, done, err := s.beginInterfaceRoleOperation(r)
	if err != nil {
		return nil, err
	}
	defer done()
	input := bgpRoutingBindingsInput{CollectorAgentID: r.URL.Query().Get("collector_agent_id"), SourceRef: r.URL.Query().Get("source_ref")}
	if r.Method == http.MethodPut {
		if err := decodeJSONLimit(r, interfaceRoleBodyBytes(budget), &input); err != nil {
			return nil, err
		}
		if input.Bindings == nil || input.ExpectedEpoch == nil {
			return nil, apierror.BadRequest("expected_epoch and complete bindings are required; an empty array withdraws all selectors")
		}
	}
	permission := ai.PermEntitiesRead
	if r.Method == http.MethodPut {
		permission = permAgentWrite
	}
	ctx, flush := scopedABACDenial(r.Context())
	defer flush(s)
	r = r.WithContext(tenancy.WithSiloTableLock(ctx))
	var body json.RawMessage
	operation := func(ctx context.Context, sc tenancy.Scope) error {
		actor := auth.PrincipalFrom(ctx)
		ctx, principal, err := s.currentRoutingAuthority(ctx, sc, actor, permission)
		if err != nil {
			return err
		}
		checked := map[string]bool{}
		authorize := func(ctx context.Context, record entity.ContextRecord) error {
			checked[record.ContextID] = true
			return s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record))
		}
		profile := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes - budget.MemoryBytes/4, WorkUnits: budget.MemoryBytes / 2, StateBytes: 1 << 30}
		configuration := store.BGPRouting{}
		var out store.BGPRoutingBindingConfiguration
		if r.Method == http.MethodPut {
			out, err = configuration.ReplaceBindingsInScope(ctx, sc, input.CollectorAgentID, input.SourceRef, r.PathValue("context_id"), *input.ExpectedEpoch, *input.Bindings, profile, authorize)
		} else {
			out, err = configuration.BindingsInScope(ctx, sc, input.CollectorAgentID, input.SourceRef, profile, authorize)
			if err == nil && out.ContextID != r.PathValue("context_id") {
				return entity.ErrScopeMismatch
			}
		}
		if err != nil {
			return err
		}
		if r.Method == http.MethodPut {
			// A source/account/target lock wait must not preserve old actor or
			// context-policy authority. Re-read every approved context before
			// publication; a failed recheck rolls back the whole replacement.
			ctx, principal, err = s.currentRoutingAuthority(ctx, sc, actor, permission)
			if err != nil {
				return err
			}
			for id := range checked {
				record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, id)
				if err != nil {
					return err
				}
				if err := authorize(ctx, record); err != nil {
					return err
				}
			}
		}
		body, err = interfaceRolePublication(out, budget)
		if err != nil || r.Method == http.MethodGet {
			return err
		}
		return s.recordAudit(ctx, sc, r.WithContext(ctx), "bgp.routing_bindings.replaced", input.SourceRef,
			map[string]any{"collector_agent_id": input.CollectorAgentID, "context_id": out.ContextID, "epoch": out.Manifest.Epoch, "binding_count": len(out.Manifest.Bindings)})
	}
	if r.Method == http.MethodGet {
		err = tenancy.InTenantReadSnapshot(r.Context(), s.pool, operation)
	} else {
		err = s.inTenant(r, operation)
	}
	return body, bgpRoutingConfigurationError(err)
}

func (s *Server) currentRoutingAuthority(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, permission string) (context.Context, *auth.Principal, error) {
	authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return nil, nil, err
	}
	ctx, principal, err := authority.requestContext(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, nil); err != nil {
		return nil, nil, err
	}
	return ctx, principal, nil
}

func bgpRoutingConfigurationError(err error) error {
	switch {
	case errors.Is(err, store.ErrBGPRoutingBindingConflict):
		return apierror.Conflict("routing configuration changed; read its current epoch and retry")
	case errors.Is(err, store.ErrBGPRoutingBudget):
		return apierror.RateLimited("complete routing configuration exceeds operation admission")
	case errors.Is(err, store.ErrBGPRoutingSourceUnavailable), errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("current routing source configuration is unavailable")
	case errors.Is(err, store.ErrBGPRoutingView):
		return apierror.Unavailable("stored routing source configuration is unavailable")
	default:
		return entityAdminError(err)
	}
}
