// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"testing"

	"github.com/ctlplne/probectl/internal/anomaly"
)

func TestSeasonalAlertDirectionPreservesMeasuredBand(t *testing.T) {
	for _, row := range []struct {
		name      string
		reading   anomaly.SeasonalState
		direction SeasonalDirection
		breach    bool
	}{
		{"default upward", anomaly.SeasonalUp, "", true},
		{"default downward", anomaly.SeasonalDown, "", true},
		{"above upward", anomaly.SeasonalUp, SeasonalAbove, true},
		{"above downward", anomaly.SeasonalDown, SeasonalAbove, false},
		{"below downward", anomaly.SeasonalDown, SeasonalBelow, true},
		{"below upward", anomaly.SeasonalUp, SeasonalBelow, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			band := &anomaly.SeasonalEvidence{Timezone: "UTC", Lower: 90, Upper: 110}
			comparison := anomaly.SeasonalComparison{State: row.reading, Evidence: band}
			for _, exact := range []*anomaly.SeasonalDecimalBand{nil, {Lower: "90", Upper: "110"}} {
				comparison.Exact = exact
				decision := seasonalRuleDecision(&comparison, row.direction)
				if decision.breached != row.breach || decision.expectation.Seasonal == nil ||
					decision.expectation.Seasonal.Direction != row.direction || decision.expectation.Seasonal.Exact != exact {
					t.Fatal("seasonal direction did not preserve the measured evidence and selected alert behavior")
				}
			}
		})
	}
}
