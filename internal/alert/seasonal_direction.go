// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import "github.com/ctlplne/probectl/internal/anomaly"

// SeasonalDirection selects the side of a measured band that may open an
// alert episode. The direction leaves the original measured band intact.
type SeasonalDirection string

const (
	SeasonalBoth  SeasonalDirection = "both"
	SeasonalAbove SeasonalDirection = "above"
	SeasonalBelow SeasonalDirection = "below"
)

func (s SeasonalDirection) valid() bool {
	switch s {
	case "", SeasonalBoth, SeasonalAbove, SeasonalBelow:
		return true
	default:
		return false
	}
}

func (s SeasonalDirection) breached(state anomaly.SeasonalState) bool {
	switch state {
	case anomaly.SeasonalUp:
		return s == "" || s == SeasonalBoth || s == SeasonalAbove
	case anomaly.SeasonalDown:
		return s == "" || s == SeasonalBoth || s == SeasonalBelow
	default:
		return false
	}
}
