// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// AlertTagDependencies uses the same deployment query admission and operation
// policy as interactive metadata reads. Missing admission refuses tagged rules;
// legacy rules retain their existing tenant-bound source.
type AlertTagDependencies struct {
	Gate             *fairness.Gate
	FlowStore        flowstore.Store
	Queries          *Server
	IncidentWindow   time.Duration
	IncidentObserver incident.Observer
}

type alertTagAuthority struct {
	principal *auth.Principal
	current   *auth.Principal
	policies  []auth.Policy
	decider   *Server
}

func alertTagPermissions() []string { return []string{permTagsRead, "test.read", "metrics.read"} }

func (a *alertTagAuthority) permits(ctx context.Context, principal *auth.Principal, resource map[string]string) bool {
	if a == nil || a.principal == nil || principal == nil || principal.TenantID != a.principal.TenantID {
		return false
	}
	for _, permission := range alertTagPermissions() {
		if reason, err := a.decider.decideLoaded(ctx, principal, permission, auth.RBACGlobal, resource, a.policies); err != nil || reason != auth.DecisionAllowed {
			return false
		}
	}
	return true
}

// Intersect the live credential (including its scopes) with freshly loaded
// user authority. Only a live request may carry its actual MFA assertion;
// source evaluation always uses the separate non-MFA read principal.
func (a *alertTagAuthority) permitsRequest(ctx context.Context, actor *auth.Principal, permission string) bool {
	if a == nil || a.current == nil || a.decider == nil {
		return false
	}
	current := &currentUserAuthority{principal: a.current, policies: a.policies}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return false
	}
	reason, err := a.decider.decide(ctx, principal, permission, auth.RBACGlobal,
		map[string]string{auth.ResourceTenantKey: principal.TenantID})
	return err == nil && reason == auth.DecisionAllowed
}

// Load the actual active user/grants/policy in the already bound tenant, not a
// role or MFA claim stored with the rule. This principal has only source-read
// permissions; it cannot authorize a human-only action or widen token scopes.
func loadAlertTagAuthority(ctx context.Context, pool *pgxpool.Pool, tenantID, userID string) (*alertTagAuthority, error) {
	current, err := loadCurrentUserAuthority(ctx, pool, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return &alertTagAuthority{decider: &Server{pool: pool}, current: current.principal,
		principal: narrowPrincipalToScopes(auth.ClonePrincipal(current.principal), alertTagPermissions()),
		policies:  current.policies}, nil
}

type alertTagMetricSource struct {
	alert.MetricSource
	pool   *pgxpool.Pool
	tenant string
	deps   AlertTagDependencies
}

func (s alertTagMetricSource) CurrentRule(ctx context.Context, rule alert.Rule) (alert.RuleMetricRead, error) {
	if rule.Metric == alert.QueryMetric {
		if s.deps.Queries == nil || s.tenant == "" || s.tenant != rule.TenantID {
			return alert.RuleMetricRead{}, apierror.Unavailable("saved-query alert source is unavailable")
		}
		return s.deps.Queries.readAlertQueryRule(ctx, s.tenant, rule)
	}
	if s.pool == nil || s.MetricSource == nil || s.deps.Gate == nil || s.tenant == "" || rule.TenantID != s.tenant || !rule.HasTagFilter || rule.Type == alert.Trap {
		return alert.RuleMetricRead{}, apierror.Unavailable("current alert metadata source is unavailable")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.deps.FlowStore)
	if err := budget.Validate(); err != nil {
		return alert.RuleMetricRead{}, apierror.Unavailable("current alert metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx = tenancy.WithTenant(ctx, tenancy.ID(s.tenant))
	release, err := s.deps.Gate.BeginQuery(ctx, s.tenant)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	defer release()
	var configuration *alert.TagFilter
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		configuration, err = (store.AlertRules{}).GetTagFilter(ctx, sc, rule.ID, rule.UpdatedAt, budget.MemoryBytes/4)
		return err
	})
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	if configuration == nil {
		return alert.RuleMetricRead{}, store.ErrAlertTagFilterChanged
	}
	authority, err := loadAlertTagAuthority(ctx, s.pool, s.tenant, configuration.OwnerUserID)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	if !authority.permits(ctx, authority.principal, map[string]string{auth.ResourceTenantKey: s.tenant}) {
		return alert.RuleMetricRead{}, apierror.Forbidden("current alert metadata source read grants are required")
	}
	// The current owner's global metric read is authorized before telemetry IO.
	// A raw test_id only nominates metadata; it never grants access to metrics
	// or attests a sender. Context policy below further limits metadata use.
	samples, err := s.Current(ctx, rule.Metric, rule.Match)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	if err := alertTagSampleBudget(ctx, s.tenant, samples, budget.MemoryBytes/4); err != nil {
		return alert.RuleMetricRead{}, err
	}
	ids := make([]string, 0, len(samples))
	for _, sample := range samples {
		if id := sample.Labels["test_id"]; id != "" && len(id) <= 128 {
			ids = append(ids, id)
		}
	}
	snapshot, err := store.NewTagSnapshots(s.pool).LoadTests(ctx, ids, budget.MemoryBytes/4)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	contexts, err := snapshot.Contexts()
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	allowed := map[string]bool{}
	for _, record := range contexts {
		if record.TenantID != s.tenant {
			return alert.RuleMetricRead{}, apierror.Unavailable("current alert metadata context is unavailable")
		}
		allowed[record.ContextID] = authority.permits(ctx, authority.principal, entityContextResource(record))
	}
	selected, err := snapshot.SelectContext(ctx, s.tenant, ids, allowed, configuration.Filter, configuration.TagIDs, budget.MemoryBytes/4)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	selectedIDs := make(map[string]bool, len(selected))
	for _, id := range selected {
		selectedIDs[id] = true
	}
	out := []alert.Sample{}
	for _, sample := range samples {
		if selectedIDs[sample.Labels["test_id"]] {
			out = append(out, sample)
		}
	}
	if err := ctx.Err(); err != nil {
		return alert.RuleMetricRead{}, err
	}
	revision, asOf, err := snapshot.Clock()
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	selection := &alert.TagSelectionReceipt{TargetKind: configuration.TargetKind, TagRevision: strconv.FormatInt(revision, 10), AsOf: asOf}
	if err := selection.Validate(); err != nil {
		return alert.RuleMetricRead{}, err
	}
	return alert.RuleMetricRead{Samples: out, TagSelection: selection}, nil
}

func alertTagSampleBudget(ctx context.Context, tenant string, samples []alert.Sample, maxBytes int64) error {
	if tenant == "" || maxBytes <= 0 || int64(len(samples)) > maxBytes/1024 {
		return store.ErrTagSnapshotBudget
	}
	used := int64(len(samples)) * 1024
	for _, sample := range samples {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sample.Labels["tenant_id"] != tenant {
			return fmt.Errorf("alert metadata metric source returned a foreign or unbound tenant")
		}
		for key, value := range sample.Labels {
			amount := int64(len(key)) + int64(len(value)) + 128
			if amount > maxBytes-used {
				return store.ErrTagSnapshotBudget
			}
			used += amount
		}
	}
	return ctx.Err()
}
