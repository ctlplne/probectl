// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"strings"
	"time"
)

const MaxFieldComparisonKeys = 300

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
	ViewID  string                  `json:"view_id"`
	Version string                  `json:"version"`
	Mode    string                  `json:"mode"`
	Measure string                  `json:"measure"`
	Cadence string                  `json:"cadence"`
	TopKeys int                     `json:"top_keys"`
	Before  FieldComparisonSlice    `json:"before"`
	After   FieldComparisonSlice    `json:"after"`
	Changes []FieldChange           `json:"changes"`
	History *FieldComparisonHistory `json:"history,omitempty"`
}

type FieldComparisonHistory struct {
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	Hours int       `json:"hours"`
}

type FieldComparisonSlice struct {
	From              time.Time `json:"from"`
	To                time.Time `json:"to"`
	Source            string    `json:"source"`
	ResolutionSeconds int       `json:"resolution_seconds"`
	TotalGroups       int       `json:"total_groups"`
	PopulationTotal   string    `json:"population_total,omitempty"`
	LastIncluded      string    `json:"last_included,omitempty"`
	FirstExcluded     string    `json:"first_excluded,omitempty"`
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

// WithDefaults applies the same defaults for an immediate or scheduled comparison.
func (input FieldComparisonInput) WithDefaults() FieldComparisonInput {
	if input.TopKeys == 0 {
		input.TopKeys = 25
	}
	if input.Mode == "rank" {
		if input.MinimumRankChange == 0 {
			input.MinimumRankChange = 1
		}
		if input.MinimumChange == "" {
			input.MinimumChange = "0"
		}
	}
	return input
}

// Validate checks configuration only. The consumer still binds the tenant,
// authorizes the exact saved plan and verifies complete source coverage.
func (input FieldComparisonInput) Validate() error {
	if _, err := QueryViewVersion(input.Version); err != nil || input.TopKeys < 1 || input.TopKeys > MaxFieldComparisonKeys ||
		input.Measure == "" || len(input.Measure) > 64 || len(input.SecondaryThresholds) > 2 {
		return errors.New("a saved query revision, primary measure and between 1 and 300 top keys are required")
	}
	switch input.Cadence {
	case "complete_week":
		if input.PeriodSeconds != 0 {
			return errors.New("a complete-week comparison uses two seven-day windows")
		}
	case "hourly_1w", "hourly_4w":
		if input.PeriodSeconds != 3600 || input.Mode != "rank" || input.MinimumRankChange != 1 {
			return errors.New("hourly history compares new membership of completed one-hour rankings")
		}
	case "previous_period", "previous_week":
		if input.PeriodSeconds != 60 && input.PeriodSeconds != 120 && input.PeriodSeconds != 300 {
			return errors.New("field comparison windows must be 60, 120 or 300 seconds")
		}
	default:
		return errors.New("unknown flow field comparison cadence")
	}
	if input.Mode != "rank" && (input.MinimumRankChange != 0 || len(input.SecondaryThresholds) != 0) ||
		input.Mode != "share" && input.ShareBasisPoints != 0 {
		return errors.New("field comparison thresholds must match its mode")
	}
	switch input.Mode {
	case "rank":
		if input.MinimumRankChange < 1 || input.MinimumRankChange > input.TopKeys || !flowFieldDecimal(input.MinimumChange, false, false) {
			return errors.New("rank comparison requires a rank step and a nonnegative traffic floor")
		}
		seen := map[string]bool{input.Measure: true}
		for _, threshold := range input.SecondaryThresholds {
			if threshold.Measure == "" || len(threshold.Measure) > 64 || seen[threshold.Measure] || !flowFieldDecimal(threshold.Minimum, false, false) {
				return errors.New("secondary thresholds need distinct measures and nonnegative decimal floors")
			}
			seen[threshold.Measure] = true
		}
	case "amount", "fanout":
		if !flowFieldDecimal(input.MinimumChange, true, input.Mode == "fanout") {
			return errors.New("amount and fan-out comparison require a positive change floor, in whole destinations for fan-out")
		}
	case "share":
		if input.ShareBasisPoints < 1 || input.ShareBasisPoints > 10000 || input.MinimumChange != "" {
			return errors.New("share comparison needs a floor between 1 and 10000 basis points")
		}
	default:
		return errors.New("unknown flow field comparison mode")
	}
	return nil
}

func flowFieldDecimal(value string, positive, integer bool) bool {
	if len(value) > 256 {
		return false
	}
	whole, fraction, hasDot := strings.Cut(value, ".")
	if whole == "" || hasDot && (integer || fraction == "") {
		return false
	}
	digits := whole + fraction
	return strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }) == -1 &&
		(!positive || strings.Trim(digits, "0") != "")
}
