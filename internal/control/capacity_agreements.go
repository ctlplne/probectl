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
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Financial configuration is deliberately independent of flow.read. A terms
// reader cannot query counters, and a telemetry reader cannot see prices.
func (s *Server) authorizeCapacityAgreement(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, mutation bool) error {
	if actor == nil || actor.UserID == "" || sc.Tenant.String() != actor.TenantID {
		return apierror.Forbidden("current tenant financial user is required")
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	permissions := []string{permFlowAgreementsRead}
	if mutation {
		permissions = append(permissions, permFlowAgreementsWrite)
	}
	for _, permission := range permissions {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) currentCapacityAgreementActor(ctx context.Context, actor *auth.Principal, mutation bool) error {
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return err
	}
	if status != "active" {
		return apierror.Forbidden("current financial tenant is inactive")
	}
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return s.authorizeCapacityAgreement(ctx, sc, actor, mutation)
	})
}

type capacityAgreementOperation struct {
	request *http.Request
	store   *flow.PostgresCapacityAgreements
	actor   *auth.Principal
	budget  flowstore.ExplorerBudget
	done    func()
}

func (s *Server) beginCapacityAgreement(r *http.Request) (capacityAgreementOperation, error) {
	return s.beginCapacityAgreementMode(r, r.Method != http.MethodGet)
}

func (s *Server) beginCapacityAgreementMode(r *http.Request, mutation bool) (capacityAgreementOperation, error) {
	none := capacityAgreementOperation{}
	actor := auth.PrincipalFrom(r.Context())
	ctx, err := bindFlowRoleContext(r.Context(), actor)
	if err != nil {
		return none, err
	}
	if s.pool == nil || s.cfg == nil || s.cfg.FlowQueryLibraryBytes <= 0 || s.fairnessGate == nil {
		return none, apierror.Unavailable("financial configuration storage or admission is unavailable")
	}
	if s.requireMFA && !actor.MFASatisfied {
		return none, apierror.Forbidden("multi-factor authentication required")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if budget.Validate() != nil {
		return none, apierror.Unavailable("financial operation admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	if err := s.currentCapacityAgreementActor(ctx, actor, mutation); err != nil {
		cancel()
		return none, err
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		cancel()
		return none, tagQueryAdmissionError(err)
	}
	repository := flow.NewPostgresCapacityAgreements(s.pool, int64(s.cfg.FlowQueryLibraryBytes), budget.MemoryBytes, budget.ReadBytes, audit.TenantRecord).
		WithExecutionLimit(budget.ExecutionLimit).
		WithAuthorization(func(ctx context.Context, sc tenancy.Scope, user string, write bool) error {
			if user != actor.UserID {
				return apierror.Forbidden("financial actor scope changed")
			}
			return s.authorizeCapacityAgreement(ctx, sc, actor, write)
		})
	return capacityAgreementOperation{request: r.WithContext(ctx), store: repository, actor: actor, budget: budget, done: func() { release(); cancel() }}, nil
}

func capacityAgreementAPIError(err error) error {
	if err == nil {
		return nil
	}
	if value, ok := apierror.As(err); ok {
		return value
	}
	switch {
	case errors.Is(err, flow.ErrCapacityAgreementNotFound):
		return apierror.NotFound("capacity agreement not found")
	case errors.Is(err, flow.ErrCapacityAgreementConflict):
		return apierror.Conflict("capacity agreement changed; refresh its revision")
	case errors.Is(err, flow.ErrCapacityAgreementInvalid):
		return apierror.Validation("complete valid capacity agreement is required")
	case errors.Is(err, flow.ErrCapacityAgreementBudget):
		return apierror.TooLarge("complete financial configuration exceeds resource admission")
	default:
		return apierror.Unavailable("financial configuration is unavailable")
	}
}

func capacityAgreementPageInput(r *http.Request) (flow.CapacityAgreementList, error) {
	input := flow.CapacityAgreementList{After: r.URL.Query().Get("after")}
	if text := r.URL.Query().Get("limit"); text != "" {
		limit, err := strconv.Atoi(text)
		if err != nil || limit <= 0 || strconv.Itoa(limit) != text {
			return input, apierror.Validation("positive exact page limit is required")
		}
		input.Limit = limit
	}
	return input, nil
}

func (s *Server) handleCapacityAgreementList(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreement(r)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	input, err := capacityAgreementPageInput(op.request)
	if err != nil {
		return err
	}
	var page flow.CapacityAgreementPage
	if id := r.PathValue("id"); id != "" {
		page, err = op.store.ListCapacityAgreementRevisions(op.request.Context(), op.actor.UserID, id, input)
	} else {
		page, err = op.store.ListCapacityAgreements(op.request.Context(), op.actor.UserID, input)
	}
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	if err := s.currentCapacityAgreementActor(op.request.Context(), op.actor, false); err != nil {
		return capacityAgreementAPIError(err)
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) handleCapacityAgreementGet(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreement(r)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	var item flow.CapacityAgreement
	version, at := r.URL.Query().Get("version"), r.URL.Query().Get("at")
	if at != "" {
		when, parseErr := time.Parse(time.RFC3339Nano, at)
		if parseErr != nil || version != "" {
			return apierror.Validation("choose either an exact revision or an RFC3339 effective instant")
		}
		item, err = op.store.CapacityAgreementAt(op.request.Context(), op.actor.UserID, r.PathValue("id"), when)
	} else {
		item, err = op.store.GetCapacityAgreement(op.request.Context(), op.actor.UserID, r.PathValue("id"), version)
	}
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	if err := s.currentCapacityAgreementActor(op.request.Context(), op.actor, false); err != nil {
		return capacityAgreementAPIError(err)
	}
	writeJSON(w, http.StatusOK, item)
	return nil
}

func (s *Server) handleCapacityAgreementSave(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreement(r)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	var input flow.SaveCapacityAgreement
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	if input.ID != "" {
		return apierror.Validation("agreement identity belongs in the path")
	}
	input.ID = r.PathValue("id")
	item, err := op.store.SaveCapacityAgreement(op.request.Context(), op.actor.UserID, input)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	if err := s.currentCapacityAgreementActor(op.request.Context(), op.actor, true); err != nil {
		return capacityAgreementAPIError(err)
	}
	status := http.StatusOK
	if input.ID == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, item)
	return nil
}

func (s *Server) handleCapacityAgreementDelete(w http.ResponseWriter, r *http.Request) error {
	op, err := s.beginCapacityAgreement(r)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	if err := op.store.DeleteCapacityAgreement(op.request.Context(), op.actor.UserID, r.PathValue("id"), r.URL.Query().Get("version")); err != nil {
		return capacityAgreementAPIError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
