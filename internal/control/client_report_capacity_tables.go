// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func projectClientReportCapacity(ctx context.Context, capture *clientReportCapture, memory int64) (reporting.CSVTable, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || bound.String() != capture.TenantID {
		return reporting.CSVTable{}, entity.ErrScopeMismatch
	}
	if memory <= 0 || int64(len(capture.Capacity)) > memory/8192 {
		return reporting.CSVTable{}, reportProjectionLimit()
	}
	p := &reportFlowProjection{ctx: ctx, tenant: capture.TenantID, memory: memory}
	rows := [][]string{}
	for _, item := range capture.Capacity {
		selection, err := json.Marshal(item.Input)
		if err != nil {
			return reporting.CSVTable{}, err
		}
		members, err := json.Marshal(item.Measurement.Members)
		if err != nil {
			return reporting.CSVTable{}, err
		}
		for _, forecast := range item.Measurement.Forecasts {
			if !forecast.From.Equal(capture.From) || !forecast.To.Equal(capture.To) {
				return reporting.CSVTable{}, entity.ErrInvalidClaim
			}
			intervals, err := json.Marshal(struct {
				Central  any `json:"central"`
				Earliest any `json:"earliest"`
				Latest   any `json:"latest"`
			}{forecast.Central, forecast.Earliest, forecast.Latest})
			if err != nil {
				return reporting.CSVTable{}, err
			}
			row := []string{capture.TenantID, string(selection), string(members), item.Measurement.MembershipBasis, item.Measurement.MaximumPollGap, item.Measurement.AsOf.UTC().Format(time.RFC3339Nano), item.OriginalRows, item.OriginalsDigest,
				forecast.Target, forecast.Direction, forecast.CounterModel, forecast.Model, forecast.IntervalMethod, forecast.From.UTC().Format(time.RFC3339Nano), forecast.To.UTC().Format(time.RFC3339Nano), forecast.Until.UTC().Format(time.RFC3339Nano),
				strconv.Itoa(forecast.ExpectedSamples), strconv.Itoa(forecast.ObservedSamples), strconv.FormatBool(forecast.CoverageComplete), strconv.FormatBool(forecast.Trained), forecast.Reason, forecast.CapacityNumerator, forecast.CapacityDenominator, forecast.TrendNumerator, forecast.TrendDenominator,
				strconv.Itoa(forecast.ObservedExceedances), strconv.FormatBool(forecast.LastSampleKnown), strconv.FormatBool(forecast.LastSampleExceeded), string(intervals)}
			if err := chargeClientReportCells(p, row); err != nil {
				return reporting.CSVTable{}, err
			}
			rows = append(rows, row)
		}
	}
	columns := plainClientReportColumns([]string{"tenant_id", "query_and_explicit_assumptions", "canonical_members", "membership_basis", "maximum_poll_gap", "captured_at", "original_row_count", "originals_digest", "target", "direction", "counter_model", "forecast_model", "interval_method", "training_from", "training_to", "forecast_until", "expected_samples", "observed_samples", "coverage_complete", "trained", "reason", "capacity_numerator", "capacity_denominator", "trend_numerator", "trend_denominator", "observed_exceedances", "last_sample_known", "last_sample_exceeded", "runout_intervals"})
	for _, index := range []int{6, 16, 17, 21, 22, 25} {
		columns[index].Numeric = true
	}
	table := sealedClientReportTable(capture.TenantID, "client-capacity", "Capacity and runout under explicit physical assumptions", capture.From, capture.To, columns, rows)
	table.Source = "complete original-counter training window, current canonical membership and explicit operator thresholds/bounds; no inventory speed or financial inference"
	if len(capture.Capacity) == 0 {
		table.Source = "no capacity targets configured; no utilization, available capacity or runout is claimed"
	}
	if err := ctx.Err(); err != nil {
		return reporting.CSVTable{}, err
	}
	return table, nil
}
