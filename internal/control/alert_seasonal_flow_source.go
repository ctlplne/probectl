// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type seasonalFlowSelection = alert.SeasonalFlowInput

func (s *Server) authorizeSeasonalFlowSelection(ctx context.Context, actor *auth.Principal, selection seasonalFlowSelection) error {
	if err := selection.Validate(); err != nil {
		return err
	}
	view, err := s.currentSeasonalFlowView(ctx, actor, selection.ViewID)
	if err != nil {
		return err
	}
	if view.Version != selection.ViewVersion {
		return apierror.Conflict("the seasonal flow view was superseded")
	}
	if view.Definition.Time.Mode != "lookback" {
		return apierror.Validation("set an Explorer lookback before selecting a seasonal flow measure")
	}
	expected := alert.QueryCondition{Mode: "threshold", Metric: selection.Measure, Comparison: alert.GTE, Threshold: "0"}
	if err := expected.Validate(view.Definition.Plan.Metrics); err != nil {
		return apierror.Validation("the specified measure is absent from the saved flow view").Wrap(err)
	}
	return ctx.Err()
}

func (s *Server) currentSeasonalFlowView(ctx context.Context, actor *auth.Principal, id string) (flow.SavedQueryView, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || bound.String() != actor.TenantID {
		return flow.SavedQueryView{}, tenancy.ErrNoTenant
	}
	authority, err := loadCurrentUserAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return flow.SavedQueryView{}, err
	}
	ctx, principal, err := authority.requestContext(ctx, actor)
	if err != nil {
		return flow.SavedQueryView{}, err
	}
	return s.getFlowViewByID(ctx, principal, id)
}

func (s *Server) authorizeSeasonalFlowRevisionInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, selection seasonalFlowSelection) error {
	if actor == nil || actor.TenantID != sc.Tenant.String() {
		return tenancy.ErrNoTenant
	}
	if _, err := s.authorizeFlowViewPrincipal(ctx, actor, false); err != nil {
		return err
	}
	reader, ok := s.flowQueryViews.(reportScopedSourceAccess)
	if !ok {
		return apierror.Unavailable("current seasonal flow ownership is unavailable")
	}
	view, err := reader.GetQueryViewAccessInScope(ctx, sc, actor.UserID, selection.ViewID)
	if err != nil {
		return s.mapFlowViewStoreError(ctx, actor, err)
	}
	if view.ID != selection.ViewID || view.TenantID != sc.Tenant.String() || view.Version != selection.ViewVersion {
		return apierror.Conflict("the seasonal flow view changed before publication")
	}
	return ctx.Err()
}

func exactSeasonalObservedAt(end time.Time) time.Time { return end.Add(-time.Millisecond) }
