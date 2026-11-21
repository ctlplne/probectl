// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ddosMatchedWindow struct {
	clocks                  anomaly.FlowFieldComparisonClocks
	beforeIndex, afterIndex int
}

func ddosReferenceEnds(weeks int, windows ...anomaly.FlowFieldComparisonClocks) []time.Time {
	ends := make([]time.Time, 0, (weeks+1)*len(windows))
	for week := weeks; week >= 0; week-- {
		for _, window := range windows {
			ends = append(ends, window.After.End.UTC().AddDate(0, 0, -7*week))
		}
	}
	return ends
}

// ddosMatchedWindows chooses the prior week or one representative original
// week. Both windows of a scheduled episode use the same reference week.
func ddosMatchedWindows(ctx context.Context, capture *reportFlowCapture, settings ddosAssessmentSettings, work int64,
	windows ...anomaly.FlowFieldComparisonClocks) ([]ddosMatchedWindow, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || tenant.String() != capture.TenantID {
		return nil, tenancy.ErrNoTenant
	}
	weeks, count := settings.Input.ReferenceWeeks(), len(windows)
	if capture.SourceGeneration < 1 || count < 1 || count > 2 || len(capture.Results) != (weeks+1)*count {
		return nil, anomaly.ErrDDoSCoverage
	}
	beforeAt, afterAt := 0, weeks*count
	if weeks > 1 {
		chosen, err := pickCapturedDDoSReference(ctx, capture, settings, count, work/4)
		if err != nil {
			return nil, err
		}
		beforeAt = slices.IndexFunc(capture.Results[:afterAt], func(result capturedReportFlow) bool { return result.Result.Query.To.Equal(chosen) })
		if beforeAt < 0 || beforeAt%count != count-1 {
			return nil, anomaly.ErrDDoSCoverage
		}
		beforeAt -= count - 1
	}
	matched := make([]ddosMatchedWindow, count)
	for i, window := range windows {
		before := capture.Results[beforeAt+i].Result.Query
		window.Before = anomaly.TrainingWindow{Start: before.From, End: before.To}
		matched[i] = ddosMatchedWindow{clocks: window, beforeIndex: beforeAt + i, afterIndex: afterAt + i}
	}
	return matched, ctx.Err()
}

func pickCapturedDDoSReference(ctx context.Context, capture *reportFlowCapture, settings ddosAssessmentSettings, windowCount int, work int64) (time.Time, error) {
	last := len(capture.Results) - 1
	latest := capture.Results[last]
	if latest.TenantID != capture.TenantID {
		return time.Time{}, tenancy.ErrNoTenant
	}
	scope, err := ddosCaptureScope(capture, settings, latest)
	if err != nil {
		return time.Time{}, err
	}
	observations := make([]anomaly.DDoSObservation, len(capture.Results))
	for i, result := range capture.Results {
		if result.TenantID != capture.TenantID {
			return time.Time{}, tenancy.ErrNoTenant
		}
		if result.Result.TagRevision != latest.Result.TagRevision || !result.TagAsOf.Equal(latest.TagAsOf) ||
			result.Result.RoleDigest != latest.Result.RoleDigest || result.Result.RoutingProof != latest.Result.RoutingProof {
			return time.Time{}, anomaly.ErrDDoSCoverage
		}
		if i < len(observations)-windowCount && len(result.Result.Rows) == 0 {
			observations[i] = anomaly.DDoSObservation{TenantID: capture.TenantID, Scope: scope, Target: settings.Target,
				Direction: settings.Input.Direction, From: result.Result.Query.From, To: result.Result.Query.To}
			continue
		}
		observation, _, err := projectDDoSWindow(ctx, result, settings, scope, work/2/int64(len(observations)))
		if err != nil {
			return time.Time{}, err
		}
		observations[i] = observation
	}
	if windowCount == 1 {
		chosen, err := anomaly.SelectDDoSWeeklyReference(ctx, observations[last], observations[:last], work/2)
		return chosen.To, err
	}
	prior := make([]anomaly.DDoSObservationPair, 0, last/2)
	for i := 0; i+1 < last-1; i += 2 {
		prior = append(prior, anomaly.DDoSObservationPair{Previous: observations[i], Current: observations[i+1]})
	}
	chosen, err := anomaly.SelectDDoSWeeklyReferencePair(ctx,
		anomaly.DDoSObservationPair{Previous: observations[last-1], Current: observations[last]}, prior, work/2)
	return chosen.Current.To, err
}

// citedDDoSClocks reconstructs the selected reference from the retained
// receipt. Reports and routing reviews continue to measure those same exact
// windows even if later traffic arrives in other reference candidates.
func citedDDoSClocks(evidence alert.DDoSEvaluationEvidence, settings ddosAssessmentSettings) (ddosEpisodeClocks, error) {
	clocks, err := ddosClocks(evidence.Current.After.To, settings.Input.PeriodSeconds)
	if err != nil {
		return ddosEpisodeClocks{}, err
	}
	for offset := 1; offset <= settings.Input.ReferenceWeeks(); offset++ {
		previous, okPrevious := validateCitedDDoSWindow(evidence.Previous, clocks.Previous, settings.Input.ReferenceMode, offset)
		current, okCurrent := validateCitedDDoSWindow(evidence.Current, clocks.Current, settings.Input.ReferenceMode, offset)
		if okPrevious && okCurrent {
			return ddosEpisodeClocks{Previous: previous, Current: current}, nil
		}
	}
	return ddosEpisodeClocks{}, alert.ErrQueryGroups
}

func validateCitedDDoSWindow(proof flow.DDoSAssessment, clocks anomaly.FlowFieldComparisonClocks, mode string, week int) (anomaly.FlowFieldComparisonClocks, bool) {
	clocks.Before = anomaly.TrainingWindow{Start: clocks.After.Start.AddDate(0, 0, -7*week), End: clocks.After.End.AddDate(0, 0, -7*week)}
	return clocks, proof.ReferenceMode == mode && proof.Before.From.Equal(clocks.Before.Start) && proof.Before.To.Equal(clocks.Before.End) &&
		proof.After.From.Equal(clocks.After.Start) && proof.After.To.Equal(clocks.After.End)
}
