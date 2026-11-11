// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Inspect under the actual reader's current source grants. A background owner's
// saved ceiling cannot authorize this read. No baseline, schedule, incident or
// delivery state is changed; absent groups remain explicitly absent.
func (s *Server) readAlertQueryGroup(ctx context.Context, actor *auth.Principal, id, key string) (alert.QueryGroupInspection, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.QueryGroupInspection{}, err
	}
	if !alert.ValidQueryGroupKey(key) {
		return alert.QueryGroupInspection{}, apierror.Validation("a canonical saved-query group handle is required")
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.QueryGroupInspection{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertRead)
	if err != nil {
		return alert.QueryGroupInspection{}, err
	}
	if s.fairnessGate == nil {
		return alert.QueryGroupInspection{}, apierror.Unavailable("saved-query group admission is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return alert.QueryGroupInspection{}, err
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
		if rule.Metric != alert.QueryMetric {
			return apierror.NotFound("saved-query source not found")
		}
		source, err = (store.AlertRules{}).GetQuerySource(ctx, sc, id, rule.UpdatedAt, budget.MemoryBytes/8)
		return err
	})
	if err != nil {
		return alert.QueryGroupInspection{}, err
	}
	if source == nil {
		return alert.QueryGroupInspection{}, apierror.NotFound("saved-query source not found")
	}
	capture, err := s.captureFlowSources(ctx, actor, []reportFlowSourceRef{{ID: source.Source.ViewID, Version: source.Source.ViewVersion}}, true, true)
	if err != nil {
		return alert.QueryGroupInspection{}, err
	}
	defer capture.Close()
	out, err := inspectAlertQueryGroup(ctx, *rule, *source, capture, key, budget.MemoryBytes/4)
	if err != nil {
		return alert.QueryGroupInspection{}, err
	}
	// Recheck both rule configuration and every actual reader/source requirement
	// at publication under the existing lifecycle/audit ordering. These are reads;
	// the source epoch and normal audit machinery supply the serialization fence.
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sourceepoch.SourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		current, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if !current.UpdatedAt.Equal(rule.UpdatedAt) {
			return store.ErrAlertQueryChanged
		}
		return s.validateReportSourcePublication(ctx, sc, actor, capture)
	})
	if err != nil {
		return alert.QueryGroupInspection{}, err
	}
	return out, nil
}

func inspectAlertQueryGroup(ctx context.Context, rule alert.Rule, source store.AlertQuerySource, capture *reportFlowCapture, key string, memory int64) (alert.QueryGroupInspection, error) {
	snapshot, err := alertQuerySnapshot(ctx, rule.TenantID, source.Source, capture, memory/2)
	if err != nil {
		return alert.QueryGroupInspection{}, err
	}
	decisions, _, err := alert.EvaluateQueryGroups(ctx, source.Source.Binding(rule.TenantID, rule.ID), snapshot, source.State, alert.QueryGroupBudget{MemoryBytes: memory, WorkUnits: memory})
	if err != nil {
		return alert.QueryGroupInspection{}, err
	}
	out := alert.QueryGroupInspection{Kind: "current_query_group", RuleID: rule.ID, GroupKey: key, ViewID: source.Source.ViewID, ViewVersion: source.Source.ViewVersion, At: snapshot.At, Condition: source.Source.Condition, BaselineInitialized: source.State.Initialized}
	for _, input := range capture.Inputs {
		if input.Period == "current" {
			out.From, out.To = input.From, input.To
		}
	}
	if out.From.IsZero() || !out.From.Before(out.To) {
		return alert.QueryGroupInspection{}, alert.ErrQueryGroups
	}
	for _, decision := range decisions {
		if decision.Key == key && decision.Present {
			out.Present = true
			out.Dimensions = maps.Clone(decision.Dimensions)
			out.ExactValue = decision.Value
			out.ConditionMet = decision.Breached
			break
		}
	}
	return out, nil
}
