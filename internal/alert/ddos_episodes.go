// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"time"

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
	if before == nil || after == nil || before.Class != after.Class || before.Service != after.Service {
		return nil, next, ctx.Err()
	}
	group, err := fieldEpisodeKey(key, string(after.Class)+"/"+after.Service, DDoSCondition, time.Time{})
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	next.Keys = append(next.Keys, group)
	if active[group] {
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
		assessment.Prefix != prefix || assessment.Direction != input.Direction ||
		before.Source != "raw" || after.Source != "raw" || before.Citation == "" || after.Citation == "" ||
		width <= 0 || before.From.IsZero() || after.From.IsZero() ||
		before.To.Sub(before.From) != width || after.To.Sub(after.From) != width ||
		!before.To.AddDate(0, 0, 7).Equal(after.To) {
		return false
	}
	detection := assessment.Detection
	return detection == nil ||
		detection.CurrentCitation == after.Citation && detection.ReferenceCitation == before.Citation &&
			detection.CurrentPackets == after.Packets && detection.ReferencePackets == before.Packets &&
			detection.CurrentBytes == after.Bytes && detection.ReferenceBytes == before.Bytes
}
