// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type FieldEpisode struct {
	GroupKey string
	SignalID string
	Change   flow.FieldChange
}

type FieldEvaluationEvidence struct {
	Comparison flow.FieldComparison `json:"comparison"`
	Signals    []FieldSignalLink    `json:"signals"`
}

type FieldSignalLink struct {
	ChangeKey  string `json:"change_key"`
	EpisodeID  string `json:"episode_id"`
	IncidentID string `json:"incident_id"`
}

func ValidFieldDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	digest, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(digest) == value
}

// EvaluateFieldEpisodes advances only a complete, newer source window. The current
// qualifying groups remain active until the next complete evaluation clears
// them. Persistence compares and commits both this state and its new signals.
func EvaluateFieldEpisodes(ctx context.Context, binding QueryGroupBinding, prior QueryGroupState, comparison flow.FieldComparison, budget QueryGroupBudget) ([]FieldEpisode, QueryGroupState, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != binding.TenantID {
		return nil, QueryGroupState{}, tenancy.ErrNoTenant
	}
	field := binding.Condition.Field
	if binding.Condition.Mode != FieldChangeCondition || field == nil || field.Validate() != nil ||
		comparison.ViewID != binding.ViewID || comparison.Version != binding.ViewVersion || field.Version != binding.ViewVersion ||
		comparison.Mode != field.Mode || comparison.Measure != field.Measure || comparison.Cadence != field.Cadence ||
		comparison.Changes == nil || comparison.TopKeys != field.TopKeys ||
		len(comparison.Changes) > 2*comparison.TopKeys ||
		comparison.Before.From.IsZero() || !comparison.Before.From.Before(comparison.Before.To) ||
		comparison.After.From.IsZero() || !comparison.After.From.Before(comparison.After.To) ||
		comparison.Before.To.After(comparison.After.From) || prior.Initialized && !prior.At.Before(comparison.After.To) {
		return nil, QueryGroupState{}, ErrQueryGroups
	}
	hours := anomaly.FlowFieldHistoryHours(anomaly.FlowFieldComparisonCadence(field.Cadence))
	history := comparison.History
	if hours == 0 && history != nil || hours > 0 && (history == nil || history.Hours != hours ||
		!history.To.Equal(comparison.After.From) || history.To.Sub(history.From) != time.Duration(hours)*time.Hour) {
		return nil, QueryGroupState{}, ErrQueryGroups
	}
	key, err := binding.StateKey()
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	previous, _, err := queryPreviousKeys(ctx, key, prior, &budget)
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	seen := map[string]bool{}
	next := QueryGroupState{Binding: key, Initialized: true, At: comparison.After.To.UTC(), Keys: []string{}}
	started := []FieldEpisode{}
	for _, change := range comparison.Changes {
		if err := ctx.Err(); err != nil {
			return nil, QueryGroupState{}, err
		}
		if err := budget.charge(1024); err != nil {
			return nil, QueryGroupState{}, err
		}
		if !ValidFieldDigest(change.Key) {
			return nil, QueryGroupState{}, ErrQueryGroups
		}
		switch change.Kind {
		case "entered_top_set", "left_top_set", "rank_shift", "amount_shift", "share_shift", "fanout_increase":
		default:
			return nil, QueryGroupState{}, ErrQueryGroups
		}
		group, err := fieldEpisodeKey(key, change.Key, change.Kind, time.Time{})
		if err != nil || seen[group] {
			return nil, QueryGroupState{}, ErrQueryGroups
		}
		seen[group] = true
		next.Keys = append(next.Keys, group)
		if previous[group] {
			continue
		}
		id, err := fieldEpisodeKey(key, group, change.Kind, next.At)
		if err != nil {
			return nil, QueryGroupState{}, err
		}
		started = append(started, FieldEpisode{GroupKey: group, SignalID: id, Change: change})
	}
	slices.Sort(next.Keys)
	return started, next, ctx.Err()
}

func fieldEpisodeKey(binding, subject, kind string, first time.Time) (string, error) {
	framed, err := json.Marshal(struct {
		Domain, Binding, Subject, Kind string
		First                          time.Time
	}{"probectl.flow-field-episode.v1", binding, subject, kind, first})
	if err != nil {
		return "", err
	}
	digest := crypto.Hash(framed)
	if len(digest) != 32 {
		return "", ErrQueryGroups
	}
	return hex.EncodeToString(digest), nil
}
