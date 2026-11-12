// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) readAlertQueryRule(ctx context.Context, tenant string, rule alert.Rule) (alert.RuleMetricRead, error) {
	if s.pool == nil || s.fairnessGate == nil || tenant == "" || tenant != rule.TenantID || !rule.Enabled || rule.Metric != alert.QueryMetric {
		return alert.RuleMetricRead{}, alert.ErrQueryGroups
	}
	if bound, present := tenancy.FromContext(ctx); present && bound.String() != tenant {
		return alert.RuleMetricRead{}, tenancy.ErrNoTenant
	}
	if err := rule.Validate(); err != nil {
		return alert.RuleMetricRead{}, err
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.RuleMetricRead{}, err
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(tenant)), budget.ExecutionLimit)
	defer cancel()
	release, err := s.fairnessGate.BeginQuery(ctx, tenant)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	defer release()
	configuration, due, err := s.loadAlertQueryRule(ctx, rule, budget.MemoryBytes/8)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	if !due {
		return alert.RuleMetricRead{Skip: true}, nil
	}
	actor, err := configuration.Source.CredentialCeiling(tenant)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	capture, err := s.captureFlowSources(ctx, actor, []reportFlowSourceRef{{ID: configuration.Source.ViewID, Version: configuration.Source.ViewVersion}}, true, true)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	defer capture.Close()
	snapshot, err := alertQuerySnapshot(ctx, tenant, configuration.Source, capture, budget.MemoryBytes/8)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	decisions, next, err := alert.EvaluateQueryGroups(ctx, configuration.Source.Binding(tenant, rule.ID), snapshot, configuration.State,
		alert.QueryGroupBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.MemoryBytes / 4})
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.AlertRules{}).CommitQueryState(ctx, sc, rule.ID, rule.UpdatedAt, *configuration, next, budget.MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error {
				return s.validateReportSourcePublication(ctx, sc, actor, capture)
			})
	})
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	samples := make([]alert.Sample, 0, len(decisions))
	for _, decision := range decisions {
		if !decision.Present {
			continue // the complete selection resolves and prunes live departures.
		}
		// Ordinary alert/incident readers receive an opaque group and Boolean
		// predicate. Private query values/dimensions need current flow grants;
		// a generic alert.read permission must not expose them implicitly.
		value, reason := 0.0, "saved-query condition not met"
		if decision.Breached {
			value, reason = 1, "saved-query condition met"
		}
		samples = append(samples, alert.Sample{Labels: map[string]string{"query_group": decision.Key, "query_view_id": configuration.Source.ViewID}, Value: value, Reason: reason})
	}
	return alert.RuleMetricRead{Samples: samples, QuerySelection: &alert.QuerySelection{TenantID: tenant, RuleID: rule.ID, Binding: next.Binding, At: next.At, Complete: true}}, nil
}

func (s *Server) loadAlertQueryRule(ctx context.Context, rule alert.Rule, memory int64) (*store.AlertQuerySource, bool, error) {
	var configuration *store.AlertQuerySource
	var due bool
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		due, err = (store.AlertRules{}).QuerySourceDue(ctx, sc, rule.ID, rule.UpdatedAt, time.Now().UTC())
		if err != nil || !due {
			return err
		}
		configuration, err = (store.AlertRules{}).GetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, memory)
		if err == nil && configuration == nil {
			return alert.ErrQueryGroups
		}
		return err
	})
	return configuration, due, err
}

func alertQuerySnapshot(ctx context.Context, tenant string, source alert.QuerySource, capture *reportFlowCapture, memory int64) (alert.QueryGroupSnapshot, error) {
	if capture == nil || capture.TenantID != tenant || capture.ObservedAt.IsZero() {
		return alert.QueryGroupSnapshot{}, alert.ErrQueryGroups
	}
	var current *capturedReportFlow
	for i := range capture.Results {
		result := &capture.Results[i]
		if result.TenantID != tenant || result.ID != source.ViewID || result.Version != source.ViewVersion {
			return alert.QueryGroupSnapshot{}, alert.ErrQueryGroups
		}
		if result.Period == "current" {
			if current != nil {
				return alert.QueryGroupSnapshot{}, alert.ErrQueryGroups
			}
			current = result
		}
	}
	if current == nil || current.Result.Coverage == nil || !current.Result.Coverage.CompleteInputs {
		return alert.QueryGroupSnapshot{}, apierror.Unavailable("complete saved-query source coverage is required for alert evaluation")
	}
	if err := source.Condition.Validate(current.Result.Query.Metrics); err != nil {
		return alert.QueryGroupSnapshot{}, apierror.Validation("the condition metric must exist in the saved query").Wrap(err)
	}
	groups, err := alertResultGroups(ctx, source.Condition, current.Result, memory)
	if err != nil {
		return alert.QueryGroupSnapshot{}, err
	}
	return alert.QueryGroupSnapshot{TenantID: tenant, ViewID: source.ViewID, ViewVersion: source.ViewVersion, At: capture.ObservedAt, Complete: true, Groups: groups}, nil
}

func alertResultGroups(ctx context.Context, condition alert.QueryCondition, result flowstore.PlanResult, memory int64) ([]alert.QueryGroup, error) {
	groups := []alert.QueryGroup{}
	appendGroup := func(dimensions map[string]string, values map[string]string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		cost := int64(256)
		for key, value := range dimensions {
			cost += int64(len(key)+len(value))*4 + 128
		}
		value := ""
		if condition.Mode == "threshold" {
			var found bool
			value, found = values[condition.Metric]
			if !found {
				return alert.ErrQueryGroups
			}
		}
		cost += int64(len(value)) * 4
		if cost > memory {
			return alert.ErrQueryGroups
		}
		memory -= cost
		groups = append(groups, alert.QueryGroup{Dimensions: dimensions, Value: value})
		return nil
	}
	if result.Query.View == "matrix" {
		for _, cell := range result.Matrix {
			if condition.Mode == "new_group" && (cell.RowOther || cell.ColumnOther) {
				continue
			}
			dimensions := make(map[string]string, len(cell.Row)+len(cell.Column)+2)
			for key, value := range cell.Row {
				dimensions["row."+key] = value
			}
			for key, value := range cell.Column {
				dimensions["column."+key] = value
			}
			if cell.RowOther {
				dimensions["@row_other"] = "true"
			}
			if cell.ColumnOther {
				dimensions["@column_other"] = "true"
			}
			if err := appendGroup(dimensions, cell.Metrics); err != nil {
				return nil, err
			}
		}
	} else {
		for _, row := range result.Rows {
			if row.Other {
				return nil, alert.ErrQueryGroups
			}
			if err := appendGroup(row.Group, row.Metrics); err != nil {
				return nil, err
			}
		}
		if result.Other != nil && condition.Mode == "threshold" {
			dimensions := maps.Clone(result.Other.Group)
			if dimensions == nil {
				dimensions = map[string]string{}
			}
			dimensions["@other"] = "true"
			if err := appendGroup(dimensions, result.Other.Metrics); err != nil {
				return nil, err
			}
		}
	}
	return groups, ctx.Err()
}
