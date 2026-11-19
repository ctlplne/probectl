// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

// prepareSeasonalFlowPeriods prepares successive observations of one pinned
// saved plan. Callers place the whole population in one admitted PlanBatch.
func (s *Server) prepareSeasonalFlowPeriods(ctx context.Context, actor *auth.Principal, ref reportFlowSourceRef, ends []time.Time, asOf time.Time, memory int64) ([]preparedReportFlow, int64, int, error) {
	if len(ends) == 0 || asOf.IsZero() {
		return nil, 0, 0, apierror.Validation("seasonal flow needs completed comparison windows")
	}
	if _, err := flow.QueryViewVersion(ref.Version); err != nil {
		return nil, 0, 0, apierror.Validation("seasonal flow requires its exact saved-query revision")
	}
	view, err := s.flowQueryViews.GetQueryView(ctx, actor.TenantID, actor.UserID, ref.ID)
	if err != nil {
		return nil, 0, 0, s.mapFlowViewStoreError(ctx, actor, err)
	}
	if view.ID != ref.ID || view.TenantID != actor.TenantID || view.Version != ref.Version {
		return nil, 0, 0, apierror.Conflict("seasonal flow source definition changed")
	}
	if err := s.authorizeFlowViewContext(ctx, actor, view); err != nil {
		return nil, 0, 0, err
	}
	if view.Definition.Time.Mode != "lookback" {
		return nil, 0, 0, apierror.Validation("seasonal flow requires an Explorer view with a moving lookback")
	}
	vocabulary, _, err := flow.QueryVocabularyFromContext(ctx, actor.TenantID)
	if err != nil {
		return nil, 0, 0, err
	}
	reserve := reportFlowPreparationReserve
	if memory < reserve || int64(vocabulary.TagDefinitionCount()) > (memory-reserve)/8192 {
		return nil, 0, 0, reportProjectionLimit()
	}
	reserve += int64(vocabulary.TagDefinitionCount()) * 8192

	// The comparison view's previous period is presentation configuration.
	// Each seasonal observation explicitly chooses its own single plan clock.
	view.Definition.Comparison = nil
	encoded, err := json.Marshal(view.Definition)
	perWindow := int64(len(encoded))*2 + 256
	if err != nil || int64(len(ends)) > (memory-reserve)/perWindow {
		return nil, 0, 0, reportProjectionLimit()
	}
	ordered := slices.Clone(ends)
	slices.SortFunc(ordered, time.Time.Compare)
	prepared := make([]preparedReportFlow, 0, len(ordered))
	for i, end := range ordered {
		if end.IsZero() || end.After(asOf) || (i > 0 && !end.After(ordered[i-1])) {
			return nil, 0, 0, apierror.Validation("seasonal flow clocks must be distinct completed windows")
		}
		source, err := s.prepareReportFlow(ctx, actor, view, end)
		if err != nil {
			return nil, 0, 0, err
		}
		prepared = append(prepared, source)
	}
	return prepared, reserve + int64(len(ordered))*perWindow, len(ordered), ctx.Err()
}

// Reports retain their normal single capture clock. A seasonal source prepares
// every comparable clock before admitting one typed batch.
func (s *Server) prepareConfiguredFlowCapture(ctx context.Context, actor *auth.Principal, refs []reportFlowSourceRef, periodEnd, now time.Time, memory int64, typed bool, opts reportFlowCaptureOptions) ([]preparedReportFlow, int64, int, error) {
	if len(opts.SeasonalPeriodEnds) == 0 {
		return s.prepareReportFlows(ctx, actor, refs, periodEnd, memory)
	}
	if !typed || len(refs) != 1 || !opts.PeriodEnd.IsZero() {
		return nil, 0, 0, apierror.Validation("seasonal captures require one pinned view and complete source clocks")
	}
	ends := opts.SeasonalPeriodEnds
	if opts.CombineSeasonal {
		// A typed grouped query materializes the pinned filters and plan
		// once. It receives the original complete clock list at execution.
		ends = ends[len(ends)-1:]
	}
	if opts.PrefixImpact != nil {
		if opts.FieldComparison != nil || opts.DDoSAssessment != nil || !opts.CombineSeasonal || len(opts.SeasonalPeriodEnds) != 1 || opts.PrefixImpact.view != refs[0] {
			return nil, 0, 0, apierror.Validation("traffic review requires the exact whole-prefix source window")
		}
		prepared, bytes, count, err := s.prepareSeasonalFlowPeriods(ctx, actor, refs[0], ends, now, memory)
		if err != nil {
			return nil, 0, 0, err
		}
		if err := opts.PrefixImpact.preparePlan(&prepared[0].current); err != nil {
			return nil, 0, 0, err
		}
		return prepared, bytes, count, ctx.Err()
	}
	if opts.DDoSAssessment != nil {
		if opts.FieldComparison != nil || !opts.CombineSeasonal || (len(opts.SeasonalPeriodEnds) != 2 && len(opts.SeasonalPeriodEnds) != 4) || opts.DDoSAssessment.View != refs[0] {
			return nil, 0, 0, apierror.Validation("flow assessment requires its complete pinned windows")
		}
		prepared, bytes, count, err := s.prepareSeasonalFlowPeriods(ctx, actor, refs[0], ends, now, memory)
		if err != nil {
			return nil, 0, 0, err
		}
		if err := opts.DDoSAssessment.preparePlan(&prepared[0].current); err != nil {
			return nil, 0, 0, err
		}
		return prepared, bytes, count, ctx.Err()
	}
	if opts.FieldComparison == nil {
		return s.prepareSeasonalFlowPeriods(ctx, actor, refs[0], ends, now, memory)
	}
	history := anomaly.FlowFieldHistoryHours(anomaly.FlowFieldComparisonCadence(opts.FieldComparison.Cadence))
	expected := 2
	if history > 0 {
		expected = history + 1
	}
	if opts.CombineSeasonal != (history > 0) || len(opts.SeasonalPeriodEnds) != expected || opts.FieldComparison.View != refs[0] {
		return nil, 0, 0, apierror.Validation("field analysis requires its complete saved-query clocks")
	}
	prepared, bytes, count, err := s.prepareSeasonalFlowPeriods(ctx, actor, refs[0], ends, now, memory)
	if err != nil {
		return nil, 0, 0, err
	}
	for i := range prepared {
		plan := &prepared[i].current
		if err := opts.FieldComparison.validatePlan(*plan); err != nil {
			return nil, 0, 0, err
		}
		// Fetch one additional original to verify a strict Top-N boundary.
		// The source, view revision and every predicate stay pinned.
		plan.RowLimit = opts.FieldComparison.TopKeys + 1
		plan.PageSize = min(plan.PageSize, plan.RowLimit)
	}
	return prepared, bytes, count, ctx.Err()
}
