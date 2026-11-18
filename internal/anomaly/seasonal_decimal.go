// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"strings"
)

var ErrSeasonalDecimal = errors.New("anomaly: exact seasonal values are unavailable or exceed admission")

// SeasonalDecimalBand preserves the source's decimal values across comparison
// and transport. Flow counters can differ while rounding to the same float.
type SeasonalDecimalBand struct {
	Current string `json:"current"`
	Median  string `json:"median"`
	Spread  string `json:"robust_spread"`
	Lower   string `json:"lower"`
	Upper   string `json:"upper"`
}

type decimalSeasonalTraining struct {
	medians   []*big.Rat
	precision int
	work      int64
}

func compareSeasonalDecimals(ctx context.Context, current string, values map[string][]string, minimum, sensitivity float64, work int64) (SeasonalState, SeasonalDecimalBand, error) {
	var band SeasonalDecimalBand
	if len(values) < 3 || !finiteSeasonalValue(minimum) || minimum <= 0 || !finiteSeasonalValue(sensitivity) || sensitivity <= 0 {
		return SeasonalUnavailable, band, ErrSeasonalDecimal
	}
	training := decimalSeasonalTraining{work: work}
	reading, err := training.parse(current)
	if err != nil {
		return SeasonalUnavailable, band, err
	}
	floor, err := training.parse(strconv.FormatFloat(minimum, 'f', -1, 64))
	if err != nil {
		return SeasonalUnavailable, band, err
	}
	coefficient, err := training.parse(strconv.FormatFloat(sensitivity, 'f', -1, 64))
	if err != nil {
		return SeasonalUnavailable, band, err
	}
	if err := training.addDates(ctx, values); err != nil {
		return SeasonalUnavailable, band, err
	}
	center, spread := training.center()
	radius := new(big.Rat).Mul(spread, coefficient)
	if radius.Cmp(floor) < 0 {
		radius = floor
	}
	lower := new(big.Rat).Sub(center, radius)
	upper := new(big.Rat).Add(center, radius)
	// Each median can add one decimal digit. MAD normalization uses four.
	// A sensitivity multiplier can contribute at most its source precision.
	precision := 2*training.precision + 8
	band = SeasonalDecimalBand{
		Current: current, Median: seasonalDecimalText(center, precision), Spread: seasonalDecimalText(spread, precision),
		Lower: seasonalDecimalText(lower, precision), Upper: seasonalDecimalText(upper, precision),
	}
	switch {
	case reading.Cmp(lower) < 0:
		return SeasonalDown, band, ctx.Err()
	case reading.Cmp(upper) > 0:
		return SeasonalUp, band, ctx.Err()
	default:
		return SeasonalNormal, band, ctx.Err()
	}
}

func (t *decimalSeasonalTraining) addDates(ctx context.Context, dates map[string][]string) error {
	keys := make([]string, 0, len(dates))
	for date := range dates {
		keys = append(keys, date)
	}
	sort.Strings(keys)
	for _, date := range keys {
		values := dates[date]
		if len(values) == 0 || int64(len(values)) > t.work {
			return ErrSeasonalDecimal
		}
		points := make([]*big.Rat, 0, len(values))
		for _, raw := range values {
			if err := ctx.Err(); err != nil {
				return err
			}
			value, err := t.parse(raw)
			if err != nil {
				return err
			}
			points = append(points, value)
		}
		t.medians = append(t.medians, medianSeasonalRat(points))
	}
	return ctx.Err()
}

func (t *decimalSeasonalTraining) parse(text string) (*big.Rat, error) {
	digits := strings.TrimPrefix(text, "-")
	whole, frac, split := strings.Cut(digits, ".")
	if whole == "" || (split && frac == "") || strings.IndexFunc(whole+frac, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return nil, ErrSeasonalDecimal
	}
	n := int64(len(text))
	if n > t.work/n {
		return nil, ErrSeasonalDecimal
	}
	t.work -= n * n
	t.precision = max(t.precision, len(frac))
	value, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, ErrSeasonalDecimal
	}
	return value, nil
}

func (t decimalSeasonalTraining) center() (*big.Rat, *big.Rat) {
	median := medianSeasonalRat(t.medians)
	deviations := make([]*big.Rat, 0, len(t.medians))
	for _, daily := range t.medians {
		deviations = append(deviations, new(big.Rat).Abs(new(big.Rat).Sub(daily, median)))
	}
	scale := big.NewRat(7413, 5000) // exact 1.4826, the same MAD scale as metric samples
	return median, new(big.Rat).Mul(medianSeasonalRat(deviations), scale)
}

func medianSeasonalRat(values []*big.Rat) *big.Rat {
	slices.SortFunc(values, (*big.Rat).Cmp)
	middle := len(values) / 2
	if len(values)%2 != 0 {
		return values[middle]
	}
	return new(big.Rat).Quo(new(big.Rat).Add(values[middle-1], values[middle]), big.NewRat(2, 1))
}

func seasonalDecimalText(value *big.Rat, decimals int) string {
	return strings.TrimRight(strings.TrimRight(value.FloatString(decimals), "0"), ".")
}
