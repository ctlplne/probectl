// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type deviceSyslogPatternFrequency struct {
	State           anomaly.SeasonalState        `json:"state"`
	ComparableWeeks int                          `json:"comparable_weeks"`
	RequiredWeeks   int                          `json:"required_weeks"`
	Band            *anomaly.SeasonalDecimalBand `json:"band,omitempty"`
	Citations       []anomaly.Citation           `json:"citations,omitempty"`
}

func compareDeviceSyslogFrequency(ctx context.Context, reader deviceSyslogPatternReader, tenant string,
	current device.SyslogPatternSelection, counts device.SyslogPatternCounts, work int64) (deviceSyslogPatternFrequency, error) {
	const minimumWeeks = 3
	result := deviceSyslogPatternFrequency{State: anomaly.SeasonalUnavailable, RequiredWeeks: minimumWeeks}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || tenant != bound.String() {
		return result, tenancy.ErrNoTenant
	}
	latest, present := syslogFrequencyObservation(tenant, current, counts)
	if !present {
		return result, nil
	}
	model, err := anomaly.NewWeeklySeasonalModel(anomaly.WeeklySeasonalConfig{
		Cadence: anomaly.SeasonalWeekly, Timezone: "UTC", MinimumDays: minimumWeeks, MinimumDeviation: 1,
	})
	if err != nil {
		return result, err
	}
	before := make([]anomaly.ExactSeasonalFeature, 0, anomaly.WeeklyTrainingWeeks)
	for _, window := range model.ComparableWindows(current.From) {
		selection := current
		selection.From, selection.To, selection.Limit = window.Start, window.End, 1
		rows, err := reader.ListSyslogPatterns(ctx, tenant, selection)
		if errors.Is(err, device.ErrSyslogPatternBudget) {
			continue
		}
		if err != nil {
			return result, err
		}
		if original, present := syslogFrequencyObservation(tenant, selection, rows); present {
			before = append(before, original)
		}
	}
	comparison, err := model.CompareDecimalSeries(ctx, tenant, latest, before, 3, work)
	result.State = comparison.State
	result.ComparableWeeks = comparison.ComparableDays
	result.RequiredWeeks = comparison.RequiredPeriods
	result.Band = comparison.Band
	result.Citations = comparison.Citations
	return result, err
}

func syslogFrequencyObservation(tenant string, selection device.SyslogPatternSelection,
	counts device.SyslogPatternCounts) (anomaly.ExactSeasonalFeature, bool) {
	// An unindexed historical row could carry the requested pattern. A quiet
	// interval alone cannot establish that a syslog source was reporting.
	if counts.UnindexedRows != 0 || len(counts.Patterns) != 1 ||
		counts.Patterns[0].ID != selection.PatternID || counts.Patterns[0].Count <= 0 {
		return anomaly.ExactSeasonalFeature{}, false
	}
	pattern := counts.Patterns[0]
	query := url.Values{"pattern_id": {pattern.ID}, "from": {selection.From.Format(time.RFC3339)},
		"to": {selection.To.Format(time.RFC3339)}}
	if selection.Device != "" {
		query.Set("device", selection.Device)
	}
	return anomaly.ExactSeasonalFeature{
		Feature: anomaly.Feature{TenantID: tenant, Plane: "device", Source: "device_syslog",
			Subject: pattern.ID, Metric: "probectl.device.syslog.pattern.events", TS: selection.From,
			Citation: "/v1/device/syslog/patterns?" + query.Encode()},
		Decimal: strconv.FormatInt(pattern.Count, 10),
	}, true
}
