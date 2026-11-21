// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

// BMPStatisticRange compares a single chosen RIB gauge. The wire type and
// optional address family are part of its identity. Counters are excluded.
type BMPStatisticRange struct {
	BMPStatisticKey
	Minimum uint64 `json:"minimum,string"`
	Maximum uint64 `json:"maximum,string"`
}

func (r BMPStatisticRange) Valid() bool {
	width, view := bmpStatisticFormat(r.Type)
	return r.Minimum <= r.Maximum && view != "" &&
		(width == 8 && r.AFI == 0 && r.SAFI == 0 || width == 11 && r.AFI != 0 && r.SAFI != 0)
}

// Evaluate classifies an exact sample. Missing data and gaps have their own
// states, so neither can be interpreted as a gauge reading of zero.
func (r BMPStatisticRange) Evaluate(report *BMPStatisticsReport, gap bool) string {
	if gap || report.Peer.Filtered {
		return "coverage_gap"
	}
	for _, sample := range report.Samples {
		if sample.BMPStatisticKey != r.BMPStatisticKey {
			continue
		}
		switch {
		case sample.Value < r.Minimum:
			return "below_range"
		case sample.Value > r.Maximum:
			return "above_range"
		default:
			return "within_range"
		}
	}
	return "missing"
}
