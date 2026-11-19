// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import "time"

// FieldComparisonInput pins an observed saved view revision. The server
// chooses completed UTC windows and uses the view's retained filters.
type FieldComparisonInput struct {
	Version             string                    `json:"version"`
	Mode                string                    `json:"mode"`
	Measure             string                    `json:"measure"`
	Cadence             string                    `json:"cadence"`
	PeriodSeconds       int                       `json:"period_seconds,omitempty"`
	TopKeys             int                       `json:"top_keys,omitempty"`
	MinimumRankChange   int                       `json:"minimum_rank_change,omitempty"`
	MinimumChange       string                    `json:"minimum_change,omitempty"`
	ShareBasisPoints    int                       `json:"share_basis_points,omitempty"`
	SecondaryThresholds []FieldSecondaryThreshold `json:"secondary_thresholds,omitempty"`
}

type FieldSecondaryThreshold struct {
	Measure string `json:"measure"`
	Minimum string `json:"minimum"`
}

type FieldComparison struct {
	ViewID  string               `json:"view_id"`
	Version string               `json:"version"`
	Mode    string               `json:"mode"`
	Measure string               `json:"measure"`
	Cadence string               `json:"cadence"`
	TopKeys int                  `json:"top_keys"`
	Before  FieldComparisonSlice `json:"before"`
	After   FieldComparisonSlice `json:"after"`
	Changes []FieldChange        `json:"changes"`
}

type FieldComparisonSlice struct {
	From              time.Time `json:"from"`
	To                time.Time `json:"to"`
	Source            string    `json:"source"`
	ResolutionSeconds int       `json:"resolution_seconds"`
	TotalGroups       int       `json:"total_groups"`
	PopulationTotal   string    `json:"population_total,omitempty"`
}

// An absent observation means the member was outside the admitted ranking.
// Observed zero and missing observations therefore have distinct encodings.
type FieldChange struct {
	Kind   string            `json:"kind"`
	Key    string            `json:"key"`
	Group  map[string]string `json:"group"`
	Before *FieldObservation `json:"before,omitempty"`
	After  *FieldObservation `json:"after,omitempty"`
	Delta  string            `json:"delta,omitempty"`
}

type FieldObservation struct {
	Rank      int               `json:"rank"`
	Value     string            `json:"value"`
	Secondary map[string]string `json:"secondary,omitempty"`
	Share     string            `json:"share,omitempty"`
	Citation  string            `json:"citation"`
}
