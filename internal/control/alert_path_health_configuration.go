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
	"net/url"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type preparedAlertPathHealth struct {
	ctx        context.Context
	source     alert.PathHealthSource
	query      *pathHealthOperation
	snapshot   pathHealthSnapshot
	credential func(context.Context) error
}

type pathHealthPublication func(context.Context, func(context.Context) error, func()) error

// Native configuration results retain the same query lease and repeat the
// complete original source/identity snapshot after redaction. REST completes
// these checks before its response and has no native publication registration.
func (s *Server) retainAlertPathHealth(ctx context.Context, prepared *preparedAlertPathHealth, rule alert.Rule, source alert.PathHealthSource, publication pathHealthPublication) (bool, error) {
	if publication == nil {
		return false, nil
	}
	expected, err := source.Binding(rule.TenantID, rule.ID)
	if err != nil {
		return false, err
	}
	err = publication(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := s.loadAlertPathHealthSource(prepared.ctx, rule, prepared.query.op.budget.MemoryBytes/8)
		if err != nil {
			return err
		}
		binding, err := current.Binding(rule.TenantID, rule.ID)
		if err != nil || binding != expected {
			return store.ErrAlertPathHealthChanged
		}
		if err := s.revalidatePathHealthSnapshot(prepared.query, prepared.snapshot); err != nil {
			return err
		}
		return prepared.credential(prepared.ctx)
	}, prepared.Close)
	return err == nil, err
}

func (p *preparedAlertPathHealth) Close() {
	if p != nil && p.query != nil {
		p.query.op.done()
		p.query = nil
	}
}

func alertPathHealthError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := apierror.As(err); ok {
		return err
	}
	if errors.Is(err, store.ErrAlertPathHealthChanged) || errors.Is(err, store.ErrAlertQueryChanged) {
		return apierror.Conflict("path alert configuration or source changed; refresh before saving")
	}
	if errors.Is(err, alert.ErrPathHealthSource) {
		return apierror.Validation("a complete owned path-health source is required")
	}
	if errors.Is(err, alert.ErrQueryGroups) {
		return apierror.TooLarge("complete path alert configuration exceeds resource admission")
	}
	return pathHealthError(err)
}

func (s *Server) prepareAlertPathHealth(ctx context.Context, actor *auth.Principal, input alert.PathHealthSourceInput, permission string, credential func(context.Context) error) (_ *preparedAlertPathHealth, resultErr error) {
	if credential == nil {
		return nil, apierror.Unauthorized("an originating credential is required")
	}
	if err := credential(ctx); err != nil {
		return nil, err
	}
	ctx, _, err := s.alertQueryRequest(ctx, actor, permission)
	if err != nil {
		return nil, err
	}
	input, err = alert.NormalizePathHealthSource(input)
	if err != nil {
		return nil, apierror.Validation("select an owned path test, canonical interface and error counter").Wrap(err)
	}
	source := alert.PathHealthSource{PathHealthSourceInput: input, Version: 1, OwnerUserID: actor.UserID, ReadGrants: alertQueryReadGrants(actor)}
	if source.Validate() != nil {
		return nil, apierror.Forbidden("the configuring credential must carry explicit read capabilities")
	}
	to := time.Now().UTC()
	values := url.Values{"health_from": {to.Add(-time.Duration(input.LookbackSeconds) * time.Second).Format(time.RFC3339Nano)},
		"health_to": {to.Format(time.RFC3339Nano)}, "health_poll_gap": {strconv.FormatInt(input.PollGapSeconds, 10) + "s"}}
	request, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), http.MethodGet, "/v1/tests/"+input.TestID+"/path/entities?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.SetPathValue("id", input.TestID)
	query, err := s.beginPathHealth(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			query.op.done()
		}
	}()
	snapshot, err := s.readPathHealth(query)
	if err != nil {
		return nil, err
	}
	found := false
	for _, hop := range snapshot.result.Items {
		if hop.Health != nil && hop.Health.InterfaceID == input.InterfaceID {
			found = true
		}
	}
	if !found || snapshot.binding == nil {
		return nil, apierror.Validation("the selected canonical interface is not on the current owned path")
	}
	if err := s.revalidatePathHealthSnapshot(query, snapshot); err != nil {
		return nil, err
	}
	// The synthetic domain request carries no bearer. Refresh the actual REST
	// request or native transport credential supplied by this caller instead.
	if err := credential(query.op.request.Context()); err != nil {
		return nil, err
	}
	return &preparedAlertPathHealth{ctx: query.op.request.Context(), source: source, query: query, snapshot: snapshot, credential: credential}, nil
}

// Configuration publication repeats current actor, context, path binding and
// source checks inside the existing RLS writer. No nested pool read can wait
// behind the writer's own source/audit locks.
func (s *Server) publishAlertPathHealth(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, prepared *preparedAlertPathHealth) error {
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, principal, permAlertWrite, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
		return err
	}
	if prepared == nil {
		return nil
	}
	registry := store.NewEntityRegistry(s.pool)
	binding, err := registry.PathTestBindingInScope(ctx, sc, prepared.source.TestID)
	before := prepared.snapshot.binding
	if err != nil || before == nil || binding.Scope != before.Scope || binding.Target != before.Target || !binding.AssignedAt.Equal(before.AssignedAt) {
		return store.ErrAlertPathHealthChanged
	}
	record, err := registry.GetEntityContextInScope(ctx, sc, binding.Scope.ContextID)
	if err != nil {
		return err
	}
	for _, permission := range []string{permTestRead, ai.PermEntitiesRead, ai.PermMetricsRead} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
			return err
		}
	}
	matched := false
	for _, check := range prepared.query.checks {
		if check.target.InterfaceID != prepared.source.InterfaceID {
			continue
		}
		matched = true
		target, err := store.NewDeviceCounterCaptures(s.pool).CurrentInterfaceInScope(ctx, sc, check.target.Scope, check.target.InterfaceID)
		if err != nil || !sameCapacityCounterInterface(target, check.target) || !target.ValidUntil.After(time.Now().UTC()) {
			return store.ErrAlertPathHealthChanged
		}
	}
	if !matched {
		return store.ErrAlertPathHealthChanged
	}
	return ctx.Err()
}

func recordAlertPathHealthAudit(ctx context.Context, sc tenancy.Scope, actor, action, id string, source *alert.PathHealthSource) error {
	data := map[string]any{"source": nil}
	if source != nil {
		data["source"] = source.PathHealthSourceInput
	}
	return audit.TenantRecord(ctx, sc, actor, action, id, data)
}

func (s *Server) createPathHealthAlertRule(ctx context.Context, actor *auth.Principal, rule alert.Rule, input alert.PathHealthSourceInput, credential func(context.Context) error, publication pathHealthPublication) (_ *alert.Rule, resultErr error) {
	defer func() { resultErr = alertPathHealthError(resultErr) }()
	prepared, err := s.prepareAlertPathHealth(ctx, actor, input, permAlertWrite, credential)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			prepared.Close()
		}
	}()
	if err := prepared.credential(prepared.ctx); err != nil {
		return nil, err
	}
	var created *alert.Rule
	err = tenancy.InTenant(tenancy.WithSiloTableLock(prepared.ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Create(ctx, sc, rule)
		if err != nil {
			return err
		}
		created, err = (store.AlertRules{}).SetPathHealthSource(ctx, sc, rule.ID, rule.UpdatedAt, &prepared.source, prepared.query.op.budget.MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error {
				return s.publishAlertPathHealth(ctx, sc, actor, prepared)
			})
		if err != nil {
			return err
		}
		if err := recordAlertPathHealthAudit(ctx, sc, actor.UserID, "alert.path_health_source.set", created.ID, &prepared.source); err != nil {
			return err
		}
		return audit.TenantRecord(ctx, sc, actor.UserID, "alert.create", created.ID, map[string]any{"name": created.Name})
	})
	if err != nil {
		return nil, err
	}
	retained, err = s.retainAlertPathHealth(ctx, prepared, *created, prepared.source, publication)
	return created, err
}

func (s *Server) readPathHealthAlertConfiguration(ctx context.Context, actor *auth.Principal, id, permission string) (*alert.Rule, *alert.PathHealthSource, error) {
	ctx, _, err := s.alertQueryRequest(ctx, actor, permission)
	if err != nil {
		return nil, nil, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if budget.Validate() != nil || s.fairnessGate == nil {
		return nil, nil, apierror.Unavailable("path alert configuration admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	var rule *alert.Rule
	var source *alert.PathHealthSource
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		rule, err = (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if rule.Metric != alert.PathHealthMetric {
			return apierror.Validation("this rule has no owned path-health source")
		}
		if permission == permAlertRead {
			source, err = (store.AlertRules{}).GetPathHealthSource(ctx, sc, id, rule.UpdatedAt, budget.MemoryBytes/8)
		}
		return err
	})
	return rule, source, err
}

func (s *Server) readAlertPathHealthSource(ctx context.Context, actor *auth.Principal, id string, credential func(context.Context) error, publication pathHealthPublication) (_ alert.PathHealthSourceState, resultErr error) {
	defer func() { resultErr = alertPathHealthError(resultErr) }()
	if credential == nil {
		return alert.PathHealthSourceState{}, apierror.Unauthorized("an originating credential is required")
	}
	if err := credential(ctx); err != nil {
		return alert.PathHealthSourceState{}, err
	}
	rule, source, err := s.readPathHealthAlertConfiguration(ctx, actor, id, permAlertRead)
	if err != nil {
		return alert.PathHealthSourceState{}, err
	}
	state := alert.PathHealthSourceState{RuleID: id, RuleUpdatedAt: rule.UpdatedAt}
	if source == nil {
		return state, credential(ctx)
	}
	prepared, err := s.prepareAlertPathHealth(ctx, actor, source.PathHealthSourceInput, permAlertRead, credential)
	if err != nil {
		return alert.PathHealthSourceState{}, err
	}
	retained := false
	defer func() {
		if !retained {
			prepared.Close()
		}
	}()
	if _, err := s.loadAlertPathHealthSource(prepared.ctx, *rule, prepared.query.op.budget.MemoryBytes/8); err != nil {
		return alert.PathHealthSourceState{}, err
	}
	if err := s.revalidatePathHealthSnapshot(prepared.query, prepared.snapshot); err != nil {
		return alert.PathHealthSourceState{}, err
	}
	if err := credential(prepared.ctx); err != nil {
		return alert.PathHealthSourceState{}, err
	}
	input := source.PathHealthSourceInput
	state.Configured, state.Source = true, &input
	retained, err = s.retainAlertPathHealth(ctx, prepared, *rule, *source, publication)
	return state, err
}

func (s *Server) setAlertPathHealthSource(ctx context.Context, actor *auth.Principal, id string, input alert.PathHealthSourceInput, credential func(context.Context) error, publication pathHealthPublication) (_ alert.PathHealthSourceState, resultErr error) {
	defer func() { resultErr = alertPathHealthError(resultErr) }()
	rule, _, err := s.readPathHealthAlertConfiguration(ctx, actor, id, permAlertWrite)
	if err != nil {
		return alert.PathHealthSourceState{}, err
	}
	prepared, err := s.prepareAlertPathHealth(ctx, actor, input, permAlertWrite, credential)
	if err != nil {
		return alert.PathHealthSourceState{}, err
	}
	retained := false
	defer func() {
		if !retained {
			prepared.Close()
		}
	}()
	var updated *alert.Rule
	if err := prepared.credential(prepared.ctx); err != nil {
		return alert.PathHealthSourceState{}, err
	}
	err = tenancy.InTenant(tenancy.WithSiloTableLock(prepared.ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		updated, err = (store.AlertRules{}).SetPathHealthSource(ctx, sc, id, rule.UpdatedAt, &prepared.source, prepared.query.op.budget.MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error {
				return s.publishAlertPathHealth(ctx, sc, actor, prepared)
			})
		if err != nil {
			return err
		}
		return recordAlertPathHealthAudit(ctx, sc, actor.UserID, "alert.path_health_source.set", id, &prepared.source)
	})
	if err != nil {
		return alert.PathHealthSourceState{}, err
	}
	result := prepared.source.PathHealthSourceInput
	retained, err = s.retainAlertPathHealth(ctx, prepared, *updated, prepared.source, publication)
	return alert.PathHealthSourceState{RuleID: id, RuleUpdatedAt: updated.UpdatedAt, Configured: true, Source: &result}, err
}

func (s *Server) clearAlertPathHealthSource(ctx context.Context, actor *auth.Principal, id string, credential func(context.Context) error) (_ alert.PathHealthSourceState, resultErr error) {
	defer func() { resultErr = alertPathHealthError(resultErr) }()
	if credential == nil {
		return alert.PathHealthSourceState{}, apierror.Unauthorized("an originating credential is required")
	}
	rule, _, err := s.readPathHealthAlertConfiguration(ctx, actor, id, permAlertWrite)
	if err != nil {
		return alert.PathHealthSourceState{}, err
	}
	if err := credential(ctx); err != nil {
		return alert.PathHealthSourceState{}, err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	var updated *alert.Rule
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		updated, err = (store.AlertRules{}).SetPathHealthSource(ctx, sc, id, rule.UpdatedAt, nil, flowstore.ExplorerOperationBudget(ctx, s.flowStore).MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error {
				return s.publishAlertPathHealth(ctx, sc, actor, nil)
			})
		if err != nil {
			return err
		}
		return recordAlertPathHealthAudit(ctx, sc, actor.UserID, "alert.path_health_source.clear", id, nil)
	})
	if err != nil {
		return alert.PathHealthSourceState{}, err
	}
	return alert.PathHealthSourceState{RuleID: id, RuleUpdatedAt: updated.UpdatedAt}, nil
}
