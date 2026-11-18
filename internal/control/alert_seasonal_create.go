// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) createSeasonalAlertRule(ctx context.Context, actor *auth.Principal, rule alert.Rule, input *alert.SeasonalBaselineInput, credential func(context.Context) error) (_ *alert.Rule, resultErr error) {
	defer func() { resultErr = alertSeasonalError(resultErr) }()
	if input == nil || rule.Type != alert.Baseline || ((rule.Metric == alert.SeasonalFlowMetric) != (input.Flow != nil)) {
		return nil, alert.ErrSeasonalSource
	}
	if credential == nil {
		return nil, apierror.Unauthorized("an originating credential is required")
	}
	if err := credential(ctx); err != nil {
		return nil, err
	}
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertWrite)
	if err != nil {
		return nil, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	source, err := s.prepareAlertSeasonalSource(ctx, actor, input)
	if err != nil {
		return nil, err
	}
	if source.Config.TestID != "" {
		if _, err := bindSeasonalTestSelector(rule, source.Config.TestID); err != nil {
			return nil, err
		}
	}
	if err := credential(ctx); err != nil {
		return nil, err
	}
	var created *alert.Rule
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rules := store.AlertRules{}
		initial, err := rules.Create(ctx, sc, rule)
		if err != nil {
			return err
		}
		created, err = s.persistAlertSeasonalSource(ctx, sc, actor, initial, source, budget.MemoryBytes/8)
		if err != nil {
			return err
		}
		return audit.TenantRecord(ctx, sc, actor.UserID, "alert.create", created.ID, map[string]any{"name": created.Name})
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}
