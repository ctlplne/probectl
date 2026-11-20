// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"time"
)

type CapacityForecastGroupInput struct {
	Kind       string                   `json:"kind"`
	Thresholds []CapacityGroupThreshold `json:"thresholds"`
}

type CapacityGroupThreshold struct {
	ContextID   string `json:"context_id"`
	InterfaceID string `json:"interface_id"`
	CapacityBPS string `json:"capacity_bps"`
}

type CapacityForecastGroup struct {
	Kind                           string                  `json:"kind"`
	TagRevision                    string                  `json:"tag_revision"`
	Members                        []CapacityGroupForecast `json:"members"`
	FirstConstraint                *CapacityGroupRunout    `json:"first_constraint,omitempty"`
	MembersWithoutCompleteForecast int                     `json:"members_without_complete_forecast"`
}

type CapacityGroupForecast struct {
	ContextID   string                   `json:"context_id"`
	InterfaceID string                   `json:"interface_id"`
	Forecasts   []CapacityForecastResult `json:"forecasts"`
}

type CapacityGroupRunout struct {
	ContextID   string                 `json:"context_id"`
	InterfaceID string                 `json:"interface_id"`
	Direction   string                 `json:"direction"`
	Window      CapacityRunoutInterval `json:"window"`
}

type capacityGroupMemberKey struct {
	context, iface string
}

// ForecastGroupMembers projects each already scoped original grid against its
// own planning threshold. It retains incomplete members alongside forecasts.
func ForecastGroupMembers(ctx context.Context, window CapacityMeasurementWindow, selected CapacityForecastGroupInput,
	direction string, until time.Time, measured []CapacityMeasuredMember,
) (*CapacityForecastGroup, error) {
	if len(measured) == 0 || len(selected.Thresholds) != len(measured) ||
		int64(len(measured)) > window.MemoryBytes/8192 || (selected.Kind != "pop" && selected.Kind != "tower") {
		return nil, errCapacityCounterInput
	}
	// The forecast models run serially. Reserve retained projections once and
	// divide work across the full population before fitting the first model.
	window.MemoryBytes -= int64(len(measured)) * 4096
	window.WorkUnits /= int64(len(measured))
	thresholds := make(map[capacityGroupMemberKey]string, len(selected.Thresholds))
	for _, threshold := range selected.Thresholds {
		key := capacityGroupMemberKey{threshold.ContextID, threshold.InterfaceID}
		if _, exists := thresholds[key]; exists || threshold.CapacityBPS == "" {
			return nil, errCapacityCounterInput
		}
		thresholds[key] = threshold.CapacityBPS
	}
	group := &CapacityForecastGroup{
		Kind:    selected.Kind,
		Members: make([]CapacityGroupForecast, 0, len(measured)),
	}
	for _, member := range measured {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := capacityGroupMemberKey{member.source.ContextID, member.source.InterfaceID}
		threshold, known := thresholds[id]
		if !known {
			return nil, errCapacityCounterInput
		}
		delete(thresholds, id)
		result, err := ForecastCapacityMeasured(ctx, window, id.iface, direction, threshold, until, []CapacityMeasuredMember{member})
		if err != nil {
			return nil, err
		}
		group.addMember(id, result)
	}
	return group, ctx.Err()
}

func (g *CapacityForecastGroup) addMember(member capacityGroupMemberKey, forecasts []CapacityForecastResult) {
	g.Members = append(g.Members, CapacityGroupForecast{ContextID: member.context, InterfaceID: member.iface, Forecasts: forecasts})
	complete := true
	for _, forecast := range forecasts {
		complete = complete && forecast.Trained && forecast.CoverageComplete
		interval := forecast.Earliest
		if forecast.Trained && forecast.CoverageComplete && interval.Reached && interval.From != nil && interval.To != nil &&
			(g.FirstConstraint == nil || interval.From.Before(*g.FirstConstraint.Window.From)) {
			g.FirstConstraint = &CapacityGroupRunout{ContextID: member.context, InterfaceID: member.iface, Direction: forecast.Direction, Window: interval}
		}
	}
	if !complete {
		g.MembersWithoutCompleteForecast++
	}
}
