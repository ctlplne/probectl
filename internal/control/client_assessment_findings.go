// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type clientAssessmentFindings struct {
	projection *reportFlowProjection
	capture    *clientReportCapture
	risks      [][]string
	gaps       [][]string
}

// Findings describe the captured originals and configured objectives. They add
// neither a risk score nor a second source reader; all existing source checks,
// publication fences and stored-artifact permissions continue to apply.
func projectClientAssessmentFindings(ctx context.Context, capture *clientReportCapture, memory int64) ([]reporting.CSVTable, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || bound.String() != capture.TenantID {
		return nil, entity.ErrScopeMismatch
	}
	if memory <= 0 || capture.From.IsZero() || !capture.To.After(capture.From) {
		return nil, reportProjectionLimit()
	}
	f := &clientAssessmentFindings{projection: &reportFlowProjection{ctx: ctx, tenant: capture.TenantID, memory: memory}, capture: capture}
	if err := f.availability(); err != nil {
		return nil, err
	}
	if err := f.objectives(); err != nil {
		return nil, err
	}
	if err := f.capacity(); err != nil {
		return nil, err
	}
	columns := plainClientReportColumns([]string{"tenant_id", "finding", "source_section", "context_id", "source_id", "name", "window_from", "window_to", "observed_value", "comparison_basis", "originals_digest"})
	tables := []reporting.CSVTable{
		sealedClientReportTable(capture.TenantID, "assessment-risks", "Observed assessment risks and capacity hot spots", capture.From, capture.To, columns, f.risks),
		sealedClientReportTable(capture.TenantID, "assessment-coverage", "Assessment measurement coverage and gaps", capture.From, capture.To, columns, f.gaps),
	}
	for i := range tables {
		tables[i].Source = "derived from the complete availability, configured SLO and capacity sections; no inferred schedule completeness, security score or financial commitment"
	}
	return tables, ctx.Err()
}

func (f *clientAssessmentFindings) add(gap bool, kind, section, contextID, id, name string, from, to time.Time, observed, basis, digest string) error {
	row := []string{f.capture.TenantID, kind, section, contextID, id, name, from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano), observed, basis, digest}
	if err := chargeClientReportCells(f.projection, row); err != nil {
		return err
	}
	if gap {
		f.gaps = append(f.gaps, row)
	} else {
		f.risks = append(f.risks, row)
	}
	return f.projection.ctx.Err()
}

func (f *clientAssessmentFindings) availability() error {
	for _, item := range f.capture.Availability {
		if item.TenantID != f.capture.TenantID || !item.From.Equal(f.capture.From) || !item.To.Equal(f.capture.To) {
			return entity.ErrScopeMismatch
		}
		add := func(gap bool, kind, value, basis string) error {
			return f.add(gap, kind, "client-availability", item.Source.ContextID, item.Source.TestID, item.Source.Name, item.From, item.To, value, basis, item.OriginalsDigest)
		}
		if item.Counts.Failed != "0" {
			if err := add(false, "failed_test_outcomes", item.Counts.Failed, "failed originals; not an outage duration or complete scheduled population"); err != nil {
				return err
			}
		}
		if err := add(true, "synthetic_observation_coverage", item.Counts.Coverage, "known="+item.Counts.AvailabilityDenominator+"; unknown="+item.Counts.Unknown+"; canceled="+item.Counts.Canceled+"; original_count="+item.OriginalCount+"; schedule completeness is not attested"); err != nil {
			return err
		}
	}
	if len(f.capture.Availability) == 0 {
		return f.add(true, "synthetic_sources_not_configured", "client-availability", "", "", "", f.capture.From, f.capture.To, "0", "no availability or reachability is claimed", "")
	}
	return nil
}

func (f *clientAssessmentFindings) objectives() error {
	for _, item := range f.capture.SLOs {
		if item.TenantID != f.capture.TenantID || item.From.IsZero() || !item.To.Equal(f.capture.To) || !item.To.After(item.From) {
			return entity.ErrScopeMismatch
		}
		gap := item.ObservedMeetsObjective == nil
		if !gap && *item.ObservedMeetsObjective {
			continue
		}
		kind := "observed_slo_breach"
		if gap {
			kind = "slo_outcome_unknown"
		}
		observed := item.Counts.AvailabilityNumerator + "/" + item.Counts.AvailabilityDenominator
		if err := f.add(gap, kind, "client-slos", "", item.Name, item.DisplayName, item.From, item.To, observed, "configured objective="+item.ObjectiveRatio+"; basis="+item.Basis+"; coverage="+item.Counts.Coverage, item.OriginalsDigest); err != nil {
			return err
		}
	}
	if len(f.capture.SLOs) == 0 {
		return f.add(true, "slo_definitions_unavailable", "client-slos", "", "", "", f.capture.From, f.capture.To, "0", "no configured service objective is evaluated", "")
	}
	return nil
}

func (f *clientAssessmentFindings) capacity() error {
	for _, item := range f.capture.Capacity {
		for _, forecast := range item.Measurement.Forecasts {
			if !forecast.From.Equal(f.capture.From) || !forecast.To.Equal(f.capture.To) {
				return entity.ErrInvalidClaim
			}
			add := func(gap bool, kind, observed, basis string) error {
				return f.add(gap, kind, "client-capacity", "", forecast.Target, forecast.Direction, forecast.From, forecast.To, observed, basis, item.OriginalsDigest)
			}
			if forecast.ObservedExceedances > 0 {
				if err := add(false, "observed_capacity_exceedances", strconv.Itoa(forecast.ObservedExceedances), "explicit operator capacity_bps="+item.Input.CapacityBPS+"; five-minute samples, not an inferred link speed"); err != nil {
					return err
				}
			}
			if !forecast.CoverageComplete || !forecast.Trained {
				if err := add(true, "capacity_forecast_coverage", strconv.Itoa(forecast.ObservedSamples)+"/"+strconv.Itoa(forecast.ExpectedSamples), "coverage_complete="+strconv.FormatBool(forecast.CoverageComplete)+"; trained="+strconv.FormatBool(forecast.Trained)+"; reason="+forecast.Reason); err != nil {
					return err
				}
			}
		}
	}
	if len(f.capture.Capacity) == 0 {
		return f.add(true, "capacity_targets_not_configured", "client-capacity", "", "", "", f.capture.From, f.capture.To, "0", "no utilization, available capacity or runout is claimed", "")
	}
	return nil
}
