// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"maps"
	"math/big"
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
	volumeFollowsTrend      bool
}

type ddosWeeklyReferenceChoice struct {
	end                time.Time
	volumeFollowsTrend [2]bool
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
	var choice ddosWeeklyReferenceChoice
	if weeks > 1 {
		var err error
		choice, err = pickCapturedDDoSReference(ctx, capture, settings, count, work/4)
		if err != nil {
			return nil, err
		}
		beforeAt = slices.IndexFunc(capture.Results[:afterAt], func(result capturedReportFlow) bool { return result.Result.Query.To.Equal(choice.end) })
		if beforeAt < 0 || beforeAt%count != count-1 {
			return nil, anomaly.ErrDDoSCoverage
		}
		beforeAt -= count - 1
	}
	matched := make([]ddosMatchedWindow, count)
	for i, window := range windows {
		before := capture.Results[beforeAt+i].Result.Query
		window.Before = anomaly.TrainingWindow{Start: before.From, End: before.To}
		matched[i] = ddosMatchedWindow{clocks: window, beforeIndex: beforeAt + i, afterIndex: afterAt + i,
			volumeFollowsTrend: choice.volumeFollowsTrend[i]}
	}
	return matched, ctx.Err()
}

func pickCapturedDDoSReference(ctx context.Context, capture *reportFlowCapture, settings ddosAssessmentSettings, windowCount int, work int64) (ddosWeeklyReferenceChoice, error) {
	last := len(capture.Results) - 1
	latest := capture.Results[last]
	if latest.TenantID != capture.TenantID {
		return ddosWeeklyReferenceChoice{}, tenancy.ErrNoTenant
	}
	scope, err := ddosCaptureScope(capture, settings, latest)
	if err != nil {
		return ddosWeeklyReferenceChoice{}, err
	}
	observations := make([]anomaly.DDoSObservation, len(capture.Results))
	historyEnd := len(observations) - windowCount
	currentRates := make([]map[ddosExporterRate]struct{}, windowCount)
	var samplingUnverified [2]bool
	// Read the current observations first so each historical window can be
	// compared with the rates reported by the same exporters at its paired clock.
	for i := last; i >= 0; i-- {
		result := capture.Results[i]
		if result.TenantID != capture.TenantID {
			return ddosWeeklyReferenceChoice{}, tenancy.ErrNoTenant
		}
		if result.Result.TagRevision != latest.Result.TagRevision || !result.TagAsOf.Equal(latest.TagAsOf) ||
			result.Result.RoleDigest != latest.Result.RoleDigest || result.Result.RoutingProof != latest.Result.RoutingProof {
			return ddosWeeklyReferenceChoice{}, anomaly.ErrDDoSCoverage
		}
		projected, err := projectDDoSWindow(ctx, result, settings, scope, work/2/int64(len(observations)))
		if i < historyEnd &&
			(len(result.Result.Rows) == 0 || errors.Is(err, errDDoSExporterCoverage) || errors.Is(err, errDDoSSampleCoverage) || errors.Is(err, errDDoSCounterIntegrity)) {
			observations[i] = anomaly.DDoSObservation{TenantID: capture.TenantID, Scope: scope, Target: settings.Target,
				Direction: settings.Input.Direction, From: result.Result.Query.From, To: result.Result.Query.To}
			continue
		}
		if err != nil {
			return ddosWeeklyReferenceChoice{}, err
		}
		if i >= historyEnd {
			currentRates[i-historyEnd] = projected.exporterRates
		} else if !maps.Equal(projected.exporterRates, currentRates[i%windowCount]) {
			projected.observation.Complete = false
		}
		if projected.evidence.Sampled && len(settings.Input.RequiredExporters) == 0 {
			samplingUnverified[i%windowCount] = true
		}
		observations[i] = projected.observation
	}
	var choice ddosWeeklyReferenceChoice
	if windowCount == 1 {
		chosen, err := anomaly.SelectDDoSWeeklyReference(ctx, observations[last], observations[:last], work/2)
		if err != nil {
			return choice, err
		}
		choice.end = chosen.To
	} else {
		prior := make([]anomaly.DDoSObservationPair, 0, last/2)
		for i := 0; i+1 < last-1; i += 2 {
			prior = append(prior, anomaly.DDoSObservationPair{Previous: observations[i], Current: observations[i+1]})
		}
		chosen, err := anomaly.SelectDDoSWeeklyReferencePair(ctx,
			anomaly.DDoSObservationPair{Previous: observations[last-1], Current: observations[last]}, prior, work/2)
		if err != nil {
			return choice, err
		}
		choice.end = chosen.Current.To
	}
	if settings.Input.Application == nil && anomaly.DDoSFastPeriod(settings.Input.PeriodSeconds) && len(observations) == 5*windowCount {
		for i := range windowCount {
			choice.volumeFollowsTrend[i] = !samplingUnverified[i] && followsDDoSWeeklyTrend(observations, windowCount, i, settings.Input.MinObservedRecords)
		}
	}
	return choice, ctx.Err()
}

// followsDDoSWeeklyTrend checks four complete original weeks and the
// current window at the same clock. It only identifies when volume by itself
// cannot distinguish the latest increase from the observed trend.
func followsDDoSWeeklyTrend(observations []anomaly.DDoSObservation, windowCount, offset, minRecords int) bool {
	var bytes, packets [5]*big.Int
	currentEnd := observations[4*windowCount+offset].To.UTC()
	for week := range bytes {
		window := observations[week*windowCount+offset]
		if !window.Complete || window.ObservedRecords < minRecords || !window.To.Equal(currentEnd.AddDate(0, 0, -7*(4-week))) {
			return false
		}
		var byteOK, packetOK bool
		bytes[week], byteOK = ddosWindowCounter(window.Bytes)
		packets[week], packetOK = ddosWindowCounter(window.Packets)
		if !byteOK || !packetOK || bytes[week].Sign() <= 0 || packets[week].Sign() <= 0 {
			return false
		}
	}
	return continuesDDoSWeeklyGrowth(bytes) && continuesDDoSWeeklyGrowth(packets)
}

func continuesDDoSWeeklyGrowth(counts [5]*big.Int) bool {
	latest := new(big.Rat).SetFrac(counts[4], counts[3])
	if counts[4].Cmp(counts[3]) <= 0 {
		return false
	}
	var withinLower, withinUpper bool
	for week := 1; week < 4; week++ {
		if counts[week].Cmp(counts[week-1]) <= 0 {
			return false
		}
		cmp := latest.Cmp(new(big.Rat).SetFrac(counts[week], counts[week-1]))
		withinLower = withinLower || cmp >= 0
		withinUpper = withinUpper || cmp <= 0
	}
	return withinLower && withinUpper
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
