// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type DDoSEpisode struct {
	GroupKey string
	SignalID string
}

type DDoSEvaluationEvidence struct {
	Previous   flow.DDoSAssessment `json:"previous"`
	Current    flow.DDoSAssessment `json:"current"`
	EpisodeID  string              `json:"episode_id"`
	IncidentID string              `json:"incident_id"`
	// TransportCoverage is derived from the stored receipt version on read.
	TransportCoverage bool `json:"-"`
}

// EvaluateDDoSEpisode requires two adjacent qualifying windows. The scheduler
// commits the returned watermark and any new episode in its tenant transaction.
func EvaluateDDoSEpisode(ctx context.Context, binding QueryGroupBinding, prior QueryGroupState, previous, current flow.DDoSAssessment,
	budget QueryGroupBudget) (*DDoSEpisode, QueryGroupState, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != binding.TenantID {
		return nil, QueryGroupState{}, tenancy.ErrNoTenant
	}
	input := binding.Condition.DDoS
	if binding.Condition.Mode != DDoSCondition || input == nil || input.Version != binding.ViewVersion {
		return nil, QueryGroupState{}, ErrQueryGroups
	}
	prefix, err := input.ValidatedPrefix()
	if err != nil || !matchesDDoSEvaluation(binding, previous, prefix.String()) || !matchesDDoSEvaluation(binding, current, prefix.String()) ||
		!previous.After.To.Equal(current.After.From) || !previous.Before.To.Equal(current.Before.From) ||
		prior.Initialized && !prior.At.Before(current.After.To) {
		return nil, QueryGroupState{}, ErrQueryGroups
	}
	if input.Application != nil {
		for _, window := range []flow.DDoSAssessment{previous, current} {
			if window.Detection != nil && window.Detection.Class == anomaly.DDoSVolumetric &&
				(window.Application == nil || window.Application.State == anomaly.DDoSApplicationAmbiguous ||
					window.Application.State == anomaly.DDoSApplicationSampling) {
				return nil, QueryGroupState{}, anomaly.ErrDDoSCoverage
			}
		}
	}
	key, err := binding.StateKey()
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	active, _, err := queryPreviousKeys(ctx, key, prior, &budget)
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	next := QueryGroupState{Binding: key, Initialized: true, At: current.After.To.UTC(), Keys: []string{}}
	before, after := previous.Detection, current.Detection
	if before == nil || after == nil {
		return nil, next, ctx.Err()
	}
	shortWindow := anomaly.DDoSFastPeriod(input.PeriodSeconds)
	groupName := string(after.Class) + "/" + after.Service
	if shortWindow {
		groupName = "protected_traffic_pressure"
	}
	group, err := fieldEpisodeKey(key, groupName, DDoSCondition, time.Time{})
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	// Once open, the short-window episode is bound to the protected scope.
	// Both observations still have to qualify before it can stay active.
	twoSpecificVectors := shortWindow && before.Class != anomaly.DDoSVolumetric && after.Class != anomaly.DDoSVolumetric
	sameVector := before.Class == after.Class && before.Service == after.Service
	alreadyOpen := active[group]
	if !sameVector && !twoSpecificVectors && (!shortWindow || !alreadyOpen) {
		return nil, next, ctx.Err()
	}
	next.Keys = append(next.Keys, group)
	if alreadyOpen {
		return nil, next, ctx.Err()
	}
	signal, err := fieldEpisodeKey(key, group, DDoSCondition, next.At)
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	return &DDoSEpisode{GroupKey: group, SignalID: signal}, next, ctx.Err()
}

func matchesDDoSEvaluation(binding QueryGroupBinding, assessment flow.DDoSAssessment, prefix string) bool {
	input := binding.Condition.DDoS
	width := time.Duration(input.PeriodSeconds) * time.Second
	before, after := assessment.Before, assessment.After
	if assessment.ViewID != binding.ViewID || assessment.Version != binding.ViewVersion ||
		assessment.Prefix != prefix || assessment.Direction != input.Direction || assessment.ReferenceMode != input.ReferenceMode ||
		before.Source != "raw" || after.Source != "raw" || before.Citation == "" || after.Citation == "" ||
		width <= 0 || before.From.IsZero() || after.From.IsZero() ||
		before.To.Sub(before.From) != width || after.To.Sub(after.From) != width ||
		!matchesDDoSReferenceClock(before.To, after.To, input.ReferenceWeeks()) {
		return false
	}
	if app := assessment.Application; app != nil {
		if input.Application == nil ||
			!app.Reference.From.Equal(before.From) || !app.Reference.To.Equal(before.To) ||
			!app.Current.From.Equal(after.From) || !app.Current.To.Equal(after.To) ||
			!ValidFieldDigest(app.Reference.Digest) || !ValidFieldDigest(app.Current.Digest) ||
			!matchesDDoSApplicationResult(app.State, assessment.Detection) {
			return false
		}
	}
	detection := assessment.Detection
	return detection == nil ||
		detection.CurrentCitation == after.Citation && detection.ReferenceCitation == before.Citation &&
			detection.CurrentPackets == after.Packets && detection.ReferencePackets == before.Packets &&
			detection.CurrentBytes == after.Bytes && detection.ReferenceBytes == before.Bytes
}

func matchesDDoSReferenceClock(before, after time.Time, maxWeeks int) bool {
	for week := 1; week <= maxWeeks; week++ {
		if before.UTC().AddDate(0, 0, 7*week).Equal(after) {
			return true
		}
	}
	return false
}

func matchesDDoSApplicationResult(state string, detection *anomaly.DDoSDetection) bool {
	switch state {
	case anomaly.DDoSApplicationDemand:
		return detection == nil
	case anomaly.DDoSApplicationObserved, anomaly.DDoSApplicationDegraded, anomaly.DDoSApplicationAmbiguous, anomaly.DDoSApplicationResidual, anomaly.DDoSApplicationSampling:
		return detection != nil && detection.Class == anomaly.DDoSVolumetric
	default:
		return false
	}
}
