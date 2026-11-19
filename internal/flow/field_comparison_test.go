// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"strings"
	"testing"
)

func TestFieldComparisonValidatesCompleteRankingAndExactDecimalFloors(t *testing.T) {
	base := FieldComparisonInput{Version: "9007199254740993", Mode: "rank", Measure: "bytes", Cadence: "hourly_4w", PeriodSeconds: 3600}
	defaults := base.WithDefaults()
	if defaults.TopKeys != 25 || defaults.MinimumRankChange != 1 || defaults.MinimumChange != "0" || defaults.Validate() != nil {
		t.Fatal("hourly comparison lost its normal defaults", defaults)
	}
	for _, cadence := range []string{"hourly_1w", "hourly_4w"} {
		bounded := defaults
		bounded.Cadence = cadence
		bounded.TopKeys = MaxFieldComparisonKeys
		bounded.MinimumChange = "9007199254740993.125"
		bounded.SecondaryThresholds = []FieldSecondaryThreshold{{Measure: "packets", Minimum: "9007199254740995"}, {Measure: "flows", Minimum: "0"}}
		if err := bounded.Validate(); err != nil {
			t.Fatal("complete hourly ranking or exact floors were refused", cadence, err)
		}
	}

	cases := []struct {
		name  string
		apply func(*FieldComparisonInput)
	}{
		{"above ranking cap", func(in *FieldComparisonInput) { in.TopKeys = MaxFieldComparisonKeys + 1 }},
		{"noncanonical view revision", func(in *FieldComparisonInput) { in.Version = "01" }},
		{"partial hour", func(in *FieldComparisonInput) { in.PeriodSeconds = 300 }},
		{"hourly amount", func(in *FieldComparisonInput) { in.Mode = "amount" }},
		{"hourly rank step", func(in *FieldComparisonInput) { in.MinimumRankChange = 2 }},
		{"partial calendar week", func(in *FieldComparisonInput) { in.Cadence = "complete_week" }},
		{"unsupported rolling period", func(in *FieldComparisonInput) { in.Cadence = "previous_period" }},
		{"unknown cadence", func(in *FieldComparisonInput) { in.Cadence = "hourly" }},
		{"incompatible share floor", func(in *FieldComparisonInput) { in.ShareBasisPoints = 1 }},
		{"negative decimal floor", func(in *FieldComparisonInput) { in.MinimumChange = "-1" }},
		{"oversized decimal floor", func(in *FieldComparisonInput) { in.MinimumChange = strings.Repeat("1", 257) }},
		{"primary measure reused", func(in *FieldComparisonInput) {
			in.SecondaryThresholds = []FieldSecondaryThreshold{{Measure: "bytes", Minimum: "1"}}
		}},
		{"secondary measure reused", func(in *FieldComparisonInput) {
			in.SecondaryThresholds = []FieldSecondaryThreshold{{Measure: "packets", Minimum: "1"}, {Measure: "packets", Minimum: "2"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := defaults
			tc.apply(&in)
			if err := in.Validate(); err == nil {
				t.Fatal("invalid ranking configuration was admitted", in)
			}
		})
	}
}

func TestFieldComparisonBindsCadenceAndThresholdsToEachMode(t *testing.T) {
	for _, tc := range []struct {
		name, mode, cadence, minimum string
		period, share                int
		accepted                     bool
	}{
		{"calendar week", "amount", "complete_week", "9007199254740993.125", 0, 0, true},
		{"one-minute amount", "amount", "previous_period", "0.00001", 60, 0, true},
		{"zero amount", "amount", "previous_period", "0.0", 60, 0, false},
		{"trailing dot", "amount", "previous_period", "1.", 60, 0, false},
		{"whole fan-out", "fanout", "previous_week", "3", 120, 0, true},
		{"fractional fan-out", "fanout", "previous_week", "3.5", 120, 0, false},
		{"maximum share", "share", "previous_week", "", 300, 10000, true},
		{"share above maximum", "share", "previous_week", "", 300, 10001, false},
		{"share with amount floor", "share", "previous_week", "1", 300, 50, false},
		{"unknown mode", "volume", "previous_period", "1", 300, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := FieldComparisonInput{Version: "1", Measure: "bytes", Mode: tc.mode, Cadence: tc.cadence,
				PeriodSeconds: tc.period, MinimumChange: tc.minimum, ShareBasisPoints: tc.share}.WithDefaults()
			if err := in.Validate(); (err == nil) != tc.accepted {
				t.Fatal("wrong field comparison verdict", in, err)
			}
		})
	}
}
