// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type preparedAlertQuery struct {
	ctx     context.Context
	cancel  context.CancelFunc
	source  alert.QuerySource
	capture *reportFlowCapture
	ceiling *auth.Principal
}

func (p *preparedAlertQuery) Close() {
	if p != nil {
		p.capture.Close()
		if p.cancel != nil {
			p.cancel()
		}
	}
}

func alertQueryReadGrants(actor *auth.Principal) []alert.QueryReadGrant {
	selected := map[auth.PermissionGrant]bool{}
	for _, grant := range actor.PermissionGrants {
		if grant.Permission == permAIQuery || reportFlowReadPermission(grant.Permission) {
			selected[grant] = true
		}
	}
	for permission, granted := range actor.Permissions {
		if granted && (permission == permAIQuery || reportFlowReadPermission(permission)) {
			selected[auth.PermissionGrant{Permission: permission, ScopeType: auth.ScopeTenant}] = true
		}
	}
	grants := make([]alert.QueryReadGrant, 0, len(selected))
	for grant := range selected {
		grants = append(grants, alert.QueryReadGrant{Permission: grant.Permission, ScopeType: grant.ScopeType, ScopeID: grant.ScopeID})
	}
	sort.Slice(grants, func(i, j int) bool {
		a, b := grants[i], grants[j]
		if a.Permission != b.Permission {
			return a.Permission < b.Permission
		}
		if a.ScopeType != b.ScopeType {
			return a.ScopeType < b.ScopeType
		}
		return a.ScopeID < b.ScopeID
	})
	return grants
}

func (s *Server) alertQueryRequest(ctx context.Context, actor *auth.Principal, permission string) (context.Context, *auth.Principal, error) {
	if actor == nil || actor.TenantID == "" || actor.UserID == "" || s.pool == nil {
		return nil, nil, apierror.Forbidden("a current tenant user is required for saved-query alerts")
	}
	if tenant, present := tenancy.FromContext(ctx); present && tenant.String() != actor.TenantID {
		return nil, nil, apierror.Forbidden("saved-query alert tenant scope is unavailable")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	current, err := loadCurrentUserAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, nil, err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
		return nil, nil, err
	}
	return ctx, principal, nil
}

func (s *Server) prepareAlertQuery(ctx context.Context, actor *auth.Principal, input alert.QuerySourceInput) (_ *preparedAlertQuery, resultErr error) {
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer func() {
		if resultErr != nil {
			cancel()
		}
	}()
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertWrite)
	if err != nil {
		return nil, err
	}
	input, err = alert.NormalizeQuerySourceInput(input)
	if err != nil {
		return nil, apierror.Validation("saved-query source requires its exact view/version, schedule and condition").Wrap(err)
	}
	source := alert.QuerySource{Version: 1, OwnerUserID: actor.UserID, ViewID: input.ViewID, ViewVersion: input.ViewVersion, EverySeconds: input.EverySeconds, Condition: input.Condition, ReadGrants: alertQueryReadGrants(actor)}
	ceiling, err := source.CredentialCeiling(actor.TenantID)
	if err != nil {
		return nil, apierror.Forbidden("the configuring credential must carry the source read capabilities").Wrap(err)
	}
	capture, err := s.captureFlowSources(ctx, ceiling, []reportFlowSourceRef{{ID: source.ViewID, Version: source.ViewVersion}}, true, false)
	if err != nil {
		return nil, err
	}
	snapshot, err := alertQuerySnapshot(ctx, actor.TenantID, source, capture, budget.MemoryBytes/8)
	if err == nil {
		// Admission has no effects or persisted state. The view ID supplies a
		// local draft namespace before a new rule has its own database ID.
		_, _, err = alert.EvaluateQueryGroups(ctx, source.Binding(actor.TenantID, source.ViewID), snapshot, alert.QueryGroupState{},
			alert.QueryGroupBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.MemoryBytes / 4})
	}
	if err != nil {
		capture.Close()
		return nil, err
	}
	return &preparedAlertQuery{ctx: ctx, cancel: cancel, source: source, capture: capture, ceiling: ceiling}, nil
}

func (s *Server) recordAlertQueryAudit(ctx context.Context, sc tenancy.Scope, actor, action, id string, source *alert.QuerySource) error {
	data := map[string]any{}
	if source != nil {
		body, err := json.Marshal(source)
		if err != nil {
			return err
		}
		data["source_digest"] = hex.EncodeToString(crypto.Hash(body))
		data["view_id"], data["view_version"], data["every_seconds"] = source.ViewID, source.ViewVersion, source.EverySeconds
	}
	return audit.TenantRecord(ctx, sc, actor, action, id, data)
}

func (s *Server) publishAlertQuery(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, prepared *preparedAlertQuery) error {
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
		return nil // explicit clear needs alert.write, with no previous criteria.
	}
	return s.validateReportSourcePublication(ctx, sc, prepared.ceiling, prepared.capture)
}

func (s *Server) createAlertRule(ctx context.Context, actor *auth.Principal, rule alert.Rule, source *alert.QuerySourceInput, recordCreate func(context.Context, tenancy.Scope, *alert.Rule) error) (*alert.Rule, error) {
	if actor == nil || actor.TenantID == "" {
		return nil, apierror.Unauthorized("authentication required")
	}
	if rule.Metric == alert.QueryMetric && source == nil {
		return nil, apierror.Validation("a saved-query rule requires its complete source at creation")
	}
	if tenant, present := tenancy.FromContext(ctx); present && tenant.String() != actor.TenantID {
		return nil, tenancy.ErrNoTenant
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	var query *preparedAlertQuery
	var err error
	if source != nil {
		query, err = s.prepareAlertQuery(ctx, actor, *source)
		if err != nil {
			return nil, err
		}
		defer query.Close()
		ctx = query.ctx
	}
	var created *alert.Rule
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := (store.AlertRules{}).Create(ctx, sc, rule)
		if e != nil {
			return e
		}
		created = x
		if query != nil {
			created, e = (store.AlertRules{}).SetQuerySource(ctx, sc, x.ID, x.UpdatedAt, &query.source, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/8,
				func(ctx context.Context, sc tenancy.Scope) error { return s.publishAlertQuery(ctx, sc, actor, query) })
			if e != nil {
				return e
			}
			if e := s.recordAlertQueryAudit(ctx, sc, actor.UserID, "alert.query_source.set", x.ID, &query.source); e != nil {
				return e
			}
		}
		if recordCreate != nil {
			return recordCreate(ctx, sc, x)
		}
		return audit.TenantRecord(ctx, sc, actor.UserID, "alert.create", x.ID, map[string]any{"name": x.Name})
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (s *Server) setAlertQuerySource(ctx context.Context, actor *auth.Principal, id string, input alert.QuerySourceInput) (alert.QuerySourceState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.QuerySourceState{}, err
	}
	prepared, err := s.prepareAlertQuery(ctx, actor, input)
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	defer prepared.Close()
	ctx = tenancy.WithSiloTableLock(prepared.ctx)
	var updated *alert.Rule
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if current.Metric != alert.QueryMetric {
			return apierror.Validation("create a saved-query condition rule before attaching its source")
		}
		updated, err = (store.AlertRules{}).SetQuerySource(ctx, sc, id, current.UpdatedAt, &prepared.source, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error {
				return s.publishAlertQuery(ctx, sc, actor, prepared)
			})
		if err != nil {
			return err
		}
		return s.recordAlertQueryAudit(ctx, sc, actor.UserID, "alert.query_source.set", id, &prepared.source)
	})
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	source := prepared.source.Input()
	return alert.QuerySourceState{RuleID: id, RuleUpdatedAt: updated.UpdatedAt, Configured: true, Source: &source}, nil
}

func (s *Server) clearAlertQuerySource(ctx context.Context, actor *auth.Principal, id string) (alert.QuerySourceState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.QuerySourceState{}, err
	}
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertWrite)
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	var updated *alert.Rule
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if current.Metric != alert.QueryMetric {
			return apierror.NotFound("saved-query alert source not found")
		}
		updated, err = (store.AlertRules{}).SetQuerySource(ctx, sc, id, current.UpdatedAt, nil, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error { return s.publishAlertQuery(ctx, sc, actor, nil) })
		if err != nil {
			return err
		}
		return s.recordAlertQueryAudit(ctx, sc, actor.UserID, "alert.query_source.clear", id, nil)
	})
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	return alert.QuerySourceState{RuleID: id, RuleUpdatedAt: updated.UpdatedAt}, nil
}

func (s *Server) readAlertQuerySource(ctx context.Context, actor *auth.Principal, id string) (alert.QuerySourceState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.QuerySourceState{}, err
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.QuerySourceState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, principal, err := s.alertQueryRequest(ctx, actor, permAlertRead)
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return alert.QuerySourceState{}, err
	}
	if s.fairnessGate == nil {
		return alert.QuerySourceState{}, apierror.Unavailable("saved-query alert source admission is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	defer release()
	var rule *alert.Rule
	var source *store.AlertQuerySource
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		rule, err = (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		source, err = (store.AlertRules{}).GetQuerySource(ctx, sc, id, rule.UpdatedAt, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/8)
		return err
	})
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	out := alert.QuerySourceState{RuleID: id, RuleUpdatedAt: rule.UpdatedAt}
	if source == nil {
		return out, nil
	}
	view, err := s.getFlowViewByID(ctx, principal, source.Source.ViewID)
	if err != nil {
		return alert.QuerySourceState{}, err
	}
	input := source.Source.Input()
	out.Configured, out.Source, out.NextAt, out.StaleRevision = true, &input, source.NextAt, view.Version != source.Source.ViewVersion
	return out, nil
}
