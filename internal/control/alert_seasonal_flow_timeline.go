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
	"github.com/ctlplne/probectl/internal/anomaly"
)

// Older weekly readers wrote up to six dates, one additional folded hour
// interval and the current input.
const seasonalFlowLegacyWindows = 8

type seasonalScopeTimeline struct {
	ID            string                       `json:"id"`
	ViewVersion   string                       `json:"view_version"`
	TagRevision   string                       `json:"tag_revision,omitempty"`
	TagAsOf       time.Time                    `json:"tag_as_of,omitempty"`
	Lookback      time.Duration                `json:"lookback_ns"`
	SharedRouting *flowRoutingSnapshotValidity `json:"shared_routing,omitempty"`
	Periods       []seasonalScopePeriod        `json:"periods"`
}

type seasonalScopePeriod struct {
	End           time.Time                    `json:"end"`
	RoutingSource bool                         `json:"routing_source,omitempty"`
	Routing       *flowRoutingSnapshotValidity `json:"routing,omitempty"`
}

// Each retained input has the same current saved view and exact lookback.
// Store repeated view metadata once while retaining each original clock and
// every routing requirement in its original window.
func compactSeasonalFlowTimeline(ctx context.Context, inputs []reportFlowInput) (*seasonalScopeTimeline, error) {
	if len(inputs) <= seasonalFlowLegacyWindows || len(inputs) > anomaly.SeasonalFlowMaximumWindows {
		return nil, alert.ErrSeasonalSource
	}
	first := inputs[0]
	common := &seasonalScopeTimeline{ID: first.ID, ViewVersion: first.Version, TagRevision: first.TagRevision,
		TagAsOf: first.TagAsOf, Lookback: first.To.Sub(first.From), Periods: make([]seasonalScopePeriod, 0, len(inputs))}
	common.SharedRouting = sharedSeasonalRouting(inputs)
	var previous time.Time
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if input.ID != common.ID || input.Version != common.ViewVersion || input.Period != "current" ||
			input.TagRevision != common.TagRevision || !input.TagAsOf.Equal(common.TagAsOf) ||
			common.Lookback <= 0 || !input.To.Add(-common.Lookback).Equal(input.From) || !input.To.After(previous) {
			return nil, alert.ErrSeasonalSource
		}
		period := seasonalScopePeriod{End: input.To, RoutingSource: input.RoutingSource, Routing: input.Routing}
		if common.SharedRouting != nil {
			period.Routing = nil
		}
		common.Periods = append(common.Periods, period)
		previous = input.To
	}
	return common, ctx.Err()
}

func sharedSeasonalRouting(inputs []reportFlowInput) *flowRoutingSnapshotValidity {
	if len(inputs) == 0 || inputs[0].Routing == nil {
		return nil
	}
	shared := inputs[0].Routing
	for _, input := range inputs {
		if !input.RoutingSource || input.Routing != shared {
			return nil
		}
	}
	return shared
}

func (s storedSeasonalFlowScope) expandedInputs(ctx context.Context, memory int64) ([]reportFlowInput, error) {
	switch s.Version {
	case 1:
		if s.Timeline != nil || len(s.Inputs) > seasonalFlowLegacyWindows {
			return nil, alert.ErrSeasonalSource
		}
		return s.Inputs, ctx.Err()
	case 2, 3:
		if len(s.Inputs) != 0 || s.Timeline == nil || (s.Version == 3) != (s.Timeline.SharedRouting != nil) {
			return nil, alert.ErrSeasonalSource
		}
		return s.Timeline.expand(ctx, memory)
	default:
		return nil, alert.ErrSeasonalSource
	}
}

func (t seasonalScopeTimeline) expand(ctx context.Context, memory int64) ([]reportFlowInput, error) {
	count := len(t.Periods)
	if count <= seasonalFlowLegacyWindows || count > anomaly.SeasonalFlowMaximumWindows || int64(count) > memory/512 || t.Lookback <= 0 {
		return nil, alert.ErrSeasonalSource
	}
	out := make([]reportFlowInput, 0, count)
	for _, p := range t.Periods {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		routing := p.Routing
		if t.SharedRouting != nil {
			if !p.RoutingSource || routing != nil {
				return nil, alert.ErrSeasonalSource
			}
			routing = t.SharedRouting
		}
		out = append(out, reportFlowInput{ID: t.ID, Version: t.ViewVersion, Period: "current", TagRevision: t.TagRevision, TagAsOf: t.TagAsOf,
			From: p.End.Add(-t.Lookback), To: p.End, RoutingSource: p.RoutingSource, Routing: routing})
	}
	return out, ctx.Err()
}
