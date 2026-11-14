// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// A trend compares modular minimum rates, not an assertion about unobserved
// counter wraps. Original pairs are retained beside the approximate local
// model statistics; current source/publication guards cover the whole input.
type pathHealthErrorTrend struct {
	Metric          string              `json:"metric"`
	State           string              `json:"state"`
	Model           string              `json:"model"`
	RateKind        string              `json:"rate_kind"`
	Sensitivity     float64             `json:"sensitivity"`
	BaselineSamples int                 `json:"baseline_samples"`
	BaselineFrom    *time.Time          `json:"baseline_from,omitempty"`
	BaselineTo      *time.Time          `json:"baseline_to,omitempty"`
	BaselineMean    *float64            `json:"baseline_mean,omitempty"`
	BaselineStddev  *float64            `json:"baseline_stddev,omitempty"`
	Score           *float64            `json:"score,omitempty"`
	Observations    []pathHealthCounter `json:"observations"`
}

func projectPathHealthErrorTrends(ctx context.Context, rows []flowstore.CounterRow, to time.Time, gap time.Duration) ([]pathHealthErrorTrend, error) {
	// Reuse the same complete-row, tenant and source-incarnation validation
	// before any model can learn. No foreign prefix is a usable baseline.
	current, err := projectPathHealth(ctx, rows, to, gap, 0)
	if err != nil {
		return nil, err
	}
	series := make(map[string][]*flowstore.CounterRow, len(pathHealthMetricNames)-2)
	for i := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rows[i].Name != pathHealthMetricNames[0] && rows[i].Name != pathHealthMetricNames[1] {
			series[rows[i].Name] = append(series[rows[i].Name], &rows[i])
		}
	}
	model := anomaly.NewLocalZScoreModel()
	result := make([]pathHealthErrorTrend, 0, len(pathHealthMetricNames)-2)
	for _, counter := range current[2:] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		trend := pathHealthErrorTrend{Metric: counter.Metric, State: "insufficient_contiguous_history", Model: model.Name(),
			RateKind: "minimum_under_counter_continuity", Sensitivity: 3, Observations: []pathHealthCounter{}}
		points := series[counter.Metric]
		sort.Slice(points, func(i, j int) bool { return points[i].PollStartedAt.Before(points[j].PollStartedAt) })
		var previous *flowstore.CounterRow
		var features []anomaly.Feature
		for i := 0; i < len(points); {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			end := i + 1
			for end < len(points) && points[end].PollStartedAt.Equal(points[i].PollStartedAt) {
				end++
			}
			if end-i != 1 {
				previous, features, trend.Observations = nil, nil, []pathHealthCounter{}
				i = end
				continue
			}
			point := points[i]
			i = end
			if previous == nil {
				previous = point
				continue
			}
			pair := projectPathHealthPair(counter.Metric, pathHealthPair{previous: previous, latest: point}, point.PollCompletedAt, gap, 0)
			previous = point
			if pair.RateKind == "unavailable" {
				features, trend.Observations = nil, []pathHealthCounter{}
				continue
			}
			rate, ok := new(big.Rat).SetString(pair.RateNumerator + "/" + pair.RateDenominator)
			if !ok {
				return nil, flowstore.ErrCounterHistoryInput
			}
			approximate, _ := rate.Float64()
			features = append(features, anomaly.Feature{TenantID: point.TenantID, Plane: "device", Source: point.AgentID + "\x00" + point.SourceRef,
				Subject: point.DeviceID + "\x00" + strconv.FormatUint(uint64(point.IfIndex), 10), Metric: point.Name, TS: point.PollStartedAt,
				Value: approximate, Citation: hex.EncodeToString(point.CaptureKey[:])})
			trend.Observations = append(trend.Observations, pair)
		}
		if len(features) > 1 {
			trend.BaselineSamples = len(features) - 1
			trend.BaselineFrom = trend.Observations[0].PreviousPollStartedAt
			trend.BaselineTo = trend.Observations[len(trend.Observations)-2].PollCompletedAt
		}
		switch {
		case counter.RateKind == "unavailable":
			trend.State = "rate_unavailable"
		case len(features) >= 4:
			findings, err := model.Evaluate(ctx, features, anomaly.Query{TenantID: rows[0].TenantID, Sensitivity: trend.Sensitivity})
			if err != nil {
				return nil, err
			}
			trend.State = "within_baseline"
			for _, finding := range findings {
				trend.State = "below_baseline"
				if finding.Direction == "up" {
					trend.State = "rising_minimum_rate"
				}
				trend.BaselineMean, trend.BaselineStddev, trend.Score = &finding.Baseline, &finding.Stddev, &finding.Score
			}
		}
		result = append(result, trend)
	}
	return result, nil
}
