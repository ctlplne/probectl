// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"math/big"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type weeklyDDoSReference struct {
	observedAt time.Time
	counters   []*big.Rat
}

// SelectDDoSWeeklyReference selects an actual observed window near the joint
// center of comparable weekly traffic. Keeping the original window preserves
// the source receipt, protocol composition and application clock.
func SelectDDoSWeeklyReference(ctx context.Context, current DDoSObservation, prior []DDoSObservation, work int64) (DDoSObservation, error) {
	var empty DDoSObservation
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return empty, ErrNoTenant
	}
	if current.TenantID != tenant.String() {
		return empty, ErrCrossTenantFeature
	}
	if len(prior) < 3 || len(prior) > 4 {
		return empty, ErrDDoSCoverage
	}
	candidates := make([]weeklyDDoSReference, 0, len(prior))
	originals := make(map[time.Time]DDoSObservation, len(prior))
	parser := decimalSeasonalTraining{work: work}
	for _, original := range prior {
		if original.TenantID != current.TenantID {
			return empty, ErrCrossTenantFeature
		}
		end := original.To.UTC()
		if _, duplicate := originals[end]; duplicate || !validDDoSWeeklyClock(end, current.To.UTC()) {
			return empty, ErrDDoSCoverage
		}
		originals[end] = original
		if !original.Complete {
			continue
		}
		if err := checkDDoSWindows(ctx, original, current); err != nil {
			return empty, err
		}
		counts, err := parseDDoSCounts(&parser, original)
		if err != nil {
			return empty, err
		}
		candidates = append(candidates, weeklyDDoSReference{observedAt: end, counters: []*big.Rat{counts.bytes, counts.packets}})
	}
	if len(candidates) < 3 {
		return empty, ErrDDoSCoverage
	}
	return originals[representativeDDoSWeek(candidates)], ctx.Err()
}

func validDDoSWeeklyClock(earlier, current time.Time) bool {
	for week := 1; week <= 4; week++ {
		if earlier.Equal(current.AddDate(0, 0, -7*week)) {
			return true
		}
	}
	return false
}

func representativeDDoSWeek(candidates []weeklyDDoSReference) time.Time {
	// Keep all counters separate. A high first window and a low second
	// window can have the same sum as two typical windows.
	centers := make([]*big.Rat, len(candidates[0].counters))
	for index := range centers {
		values := make([]*big.Rat, 0, len(candidates))
		for _, candidate := range candidates {
			values = append(values, candidate.counters[index])
		}
		centers[index] = medianDDoSReference(values)
	}
	var selected time.Time
	var best *big.Rat
	for _, candidate := range candidates {
		distance := new(big.Rat)
		for i, center := range centers {
			distance.Add(distance, relativeDDoSReferenceDistance(candidate.counters[i], center))
		}
		if best == nil || distance.Cmp(best) < 0 || distance.Cmp(best) == 0 && candidate.observedAt.After(selected) {
			selected, best = candidate.observedAt, distance
		}
	}
	return selected
}

func medianDDoSReference(values []*big.Rat) *big.Rat {
	slices.SortFunc(values, (*big.Rat).Cmp)
	lower, upper := values[(len(values)-1)/2], values[len(values)/2]
	return new(big.Rat).Quo(new(big.Rat).Add(lower, upper), big.NewRat(2, 1))
}

func relativeDDoSReferenceDistance(amount, center *big.Rat) *big.Rat {
	distance := new(big.Rat).Abs(new(big.Rat).Sub(amount, center))
	if center.Sign() > 0 {
		distance.Quo(distance, center)
	}
	return distance
}

// DDoSObservationPair holds both adjacent original observations of one week.
type DDoSObservationPair struct {
	Previous DDoSObservation
	Current  DDoSObservation
}

// SelectDDoSWeeklyReferencePair keeps both original clocks in one
// representative week. Sources use the returned individual windows for
// application context and audit receipts.
func SelectDDoSWeeklyReferencePair(ctx context.Context, current DDoSObservationPair, prior []DDoSObservationPair, work int64) (DDoSObservationPair, error) {
	var empty DDoSObservationPair
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return empty, ErrNoTenant
	}
	if current.Previous.TenantID != tenant.String() || current.Current.TenantID != tenant.String() {
		return empty, ErrCrossTenantFeature
	}
	if len(prior) < 3 || len(prior) > 4 || !adjacentDDoSWeeklyPair(current) {
		return empty, ErrDDoSCoverage
	}
	candidates := make([]weeklyDDoSReference, 0, len(prior))
	originals := make(map[time.Time]DDoSObservationPair, len(prior))
	parser := decimalSeasonalTraining{work: work}
	for _, pair := range prior {
		if pair.Previous.TenantID != tenant.String() || pair.Current.TenantID != tenant.String() {
			return empty, ErrCrossTenantFeature
		}
		end := pair.Current.To.UTC()
		if _, duplicate := originals[end]; duplicate || !adjacentDDoSWeeklyPair(pair) ||
			!validDDoSWeeklyClock(end, current.Current.To.UTC()) {
			return empty, ErrDDoSCoverage
		}
		originals[end] = pair
		if !pair.Previous.Complete || !pair.Current.Complete {
			continue
		}
		projected, err := rankableDDoSWeeklyPair(ctx, pair, current, &parser)
		if err != nil {
			return empty, err
		}
		candidates = append(candidates, projected)
	}
	if len(candidates) < 3 {
		return empty, ErrDDoSCoverage
	}
	return originals[representativeDDoSWeek(candidates)], ctx.Err()
}

func adjacentDDoSWeeklyPair(pair DDoSObservationPair) bool {
	return pair.Previous.To.Equal(pair.Current.From) &&
		pair.Previous.To.Sub(pair.Previous.From) == pair.Current.To.Sub(pair.Current.From)
}

func rankableDDoSWeeklyPair(ctx context.Context, prior, current DDoSObservationPair, parser *decimalSeasonalTraining) (weeklyDDoSReference, error) {
	summary := weeklyDDoSReference{observedAt: prior.Current.To.UTC(), counters: make([]*big.Rat, 0, 4)}
	for _, side := range [][2]DDoSObservation{{prior.Previous, current.Previous}, {prior.Current, current.Current}} {
		if err := checkDDoSWindows(ctx, side[0], side[1]); err != nil {
			return weeklyDDoSReference{}, err
		}
		count, err := parseDDoSCounts(parser, side[0])
		if err != nil {
			return weeklyDDoSReference{}, err
		}
		summary.counters = append(summary.counters, count.bytes, count.packets)
	}
	return summary, ctx.Err()
}
