// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ownedSeasonalFlowComparison struct {
	Subject string
	Result  anomaly.ExactSeasonalComparison
}

type ownedSeasonalFlowRead struct {
	At        time.Time
	Capture   *reportFlowCapture
	Principal *auth.Principal
	Scores    []ownedSeasonalFlowComparison
}

// The caller owns the returned capture until its final source check and
// prospective incident publication. The capture grants no reader authority.
func (s *Server) readSeasonalFlow(ctx context.Context, actor *auth.Principal, rule alert.Rule, selection seasonalFlowSelection, model anomaly.WeeklySeasonalModel, at time.Time) (_ ownedSeasonalFlowRead, resultErr error) {
	var empty ownedSeasonalFlowRead
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || rule.TenantID != actor.TenantID || bound.String() != rule.TenantID {
		return empty, tenancy.ErrNoTenant
	}
	observation, end := model.LatestCompletedSlot(at)
	if end.IsZero() {
		return empty, alert.ErrSeasonalSource
	}
	prior := model.ComparableCompleteEnds(observation)
	ends := append(prior, end)
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return empty, err
	}
	ref := reportFlowSourceRef{ID: selection.ViewID, Version: selection.ViewVersion}
	capture, err := s.captureFlowSourcesWithOptions(ctx, actor, []reportFlowSourceRef{ref}, true, false, reportFlowCaptureOptions{
		SeasonalPeriodEnds: ends, ReservedMemoryBytes: budget.MemoryBytes / 4,
	})
	if err != nil {
		return empty, err
	}
	defer func() {
		if resultErr != nil {
			capture.Close()
		}
	}()
	population, err := projectSeasonalFlow(ctx, capture, ref, selection.Measure, ends, budget.MemoryBytes/8)
	if err != nil {
		return empty, err
	}
	scores, err := scoreAdmittedSeasonalFlow(ctx, rule, population, model, budget.MemoryBytes/8)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return ownedSeasonalFlowRead{At: observation, Capture: capture, Principal: actor, Scores: scores}, nil
}

func scoreAdmittedSeasonalFlow(ctx context.Context, rule alert.Rule, population seasonalFlowPopulation, model anomaly.WeeklySeasonalModel, work int64) ([]ownedSeasonalFlowComparison, error) {
	keys := make([]string, 0, len(population.current))
	for key := range population.current {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	perSeries := work / int64(max(1, len(keys)))
	out := make([]ownedSeasonalFlowComparison, 0, len(keys))
	for _, key := range keys {
		result, err := model.CompareDecimalSeries(ctx, rule.TenantID, population.current[key], population.before[key], rule.Sensitivity, perSeries)
		if err != nil {
			return nil, err
		}
		out = append(out, ownedSeasonalFlowComparison{Subject: key, Result: result})
	}
	return out, ctx.Err()
}
