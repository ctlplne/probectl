// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ddosAssessmentSettings struct {
	View              reportFlowSourceRef
	Input             flow.DDoSAssessmentInput
	Target            netip.Prefix
	SideField         string
	Origins           []store.PrefixImpactFlowBinding
	IncludeSources    bool
	Cited             bool
	TransportCoverage bool
	MixedVectors      bool
	readApplication   ddosApplicationReader
}

func (s *Server) handleFlowDDoSAssessment(w http.ResponseWriter, r *http.Request) error {
	actor, err := s.flowViewPrincipal(r, false)
	if err != nil {
		return err
	}
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()
	var input flow.DDoSAssessmentInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID))
	settings, err := normalizeDDoSAssessment(r.PathValue("id"), input)
	if err != nil {
		return err
	}
	result, err := s.readFlowDDoSAssessment(ctx, actor, settings, time.Now(), nil)
	if err != nil {
		return err
	}
	if err := s.pathAlertRequestCredential(r, actor)(ctx); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (b nativeMCPFlowBackend) AssessFlowViewDDoS(ctx context.Context, actor *auth.Principal, id string, input flow.DDoSAssessmentInput) (flow.DDoSAssessment, error) {
	if err := b.authorize(ctx, actor); err != nil {
		return flow.DDoSAssessment{}, err
	}
	settings, err := normalizeDDoSAssessment(id, input)
	if err != nil {
		return flow.DDoSAssessment{}, err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	return b.server.readFlowDDoSAssessment(ctx, actor, settings, time.Now(), mcp.RetainNativePublication)
}

func normalizeDDoSAssessment(viewID string, input flow.DDoSAssessmentInput) (ddosAssessmentSettings, error) {
	var empty ddosAssessmentSettings
	target, err := input.ValidatedPrefix()
	if err != nil {
		return empty, apierror.Validation(err.Error())
	}
	if !reportRequirementUUID(viewID) {
		return empty, apierror.Validation("the assessment needs an exact saved flow view revision")
	}
	side := "dst_addr"
	if input.Direction == "egress" {
		side = "src_addr"
	}
	input.RequiredExporters = slices.Clone(input.RequiredExporters)
	slices.Sort(input.RequiredExporters)
	return ddosAssessmentSettings{View: reportFlowSourceRef{ID: viewID, Version: input.Version}, Input: input, Target: target, SideField: side}, nil
}

func (settings ddosAssessmentSettings) groupSampledExporters() bool {
	return !settings.Cited && len(settings.Input.RequiredExporters) == 0 && anomaly.DDoSFastPeriod(settings.Input.PeriodSeconds)
}

func (settings ddosAssessmentSettings) thresholds() anomaly.DDoSThresholds {
	limits := settings.Input.Thresholds()
	limits.MixedVectors = anomaly.DDoSFastPeriod(settings.Input.PeriodSeconds) && (!settings.Cited || settings.MixedVectors)
	return limits
}

func (settings ddosAssessmentSettings) preparePlan(plan *flow.QueryPlan) error {
	width := time.Duration(settings.Input.PeriodSeconds) * time.Second
	savedWidth := plan.To.Sub(plan.From)
	if plan.Cursor != "" || savedWidth < width || savedWidth != width && !anomaly.DDoSFastPeriod(settings.Input.PeriodSeconds) {
		return apierror.Validation("the saved flow lookback must cover the assessment window")
	}
	// Short observations retain the saved view's exact filters and
	// authorization while querying only its last completed subwindow.
	plan.From = plan.To.Add(-width)
	condition := flow.QueryPredicate{Field: settings.SideField, Op: flow.QueryCIDR, Values: []string{settings.Target.String()}}
	base := plan.Filter
	bound := &flow.QueryFilterGroup{Mode: "include", Match: "all", Conditions: []flow.QueryPredicate{condition}}
	if len(settings.Input.RequiredExporters) != 0 {
		bound.Conditions = append(bound.Conditions, flow.QueryPredicate{
			Field: "exporter", Op: flow.QueryIn, Values: slices.Clone(settings.Input.RequiredExporters),
		})
	}
	if base != nil {
		if base.Mode == "include" && base.Match == "all" {
			bound = &flow.QueryFilterGroup{Mode: base.Mode, Match: base.Match, Groups: base.Groups, Saved: base.Saved,
				Conditions: append(slices.Clone(base.Conditions), bound.Conditions...)}
		} else {
			bound.Groups = []flow.QueryFilterGroup{*base}
		}
	}
	if len(settings.Origins) > 0 {
		bound.Groups = append(slices.Clone(bound.Groups), prefixImpactSenderGroup(settings.Origins))
	}
	plan.Filter, plan.View, plan.DataSeries = bound, "table", "raw"
	plan.GroupBy, plan.MatrixWith = []string{settings.SideField, "transport", "tcp_flags", "src_port", "sampling"}, nil
	if settings.Input.Application != nil {
		plan.GroupBy = append(plan.GroupBy, "dst_port")
	}
	if settings.IncludeSources && settings.SideField != "src_addr" {
		plan.GroupBy = append(plan.GroupBy, "src_addr")
	}
	if len(settings.Input.RequiredExporters) != 0 || settings.groupSampledExporters() {
		plan.GroupBy = append(plan.GroupBy, "exporter")
	}
	plan.Metrics = []flow.QueryMetric{
		{Measure: "bytes", Calculation: "total", Role: "primary"},
		{Measure: "packets", Calculation: "total", Role: "additional"},
		{Measure: "flows", Calculation: "total", Role: "additional"},
	}
	plan.RowLimit, plan.PageSize = 25, 25
	return nil
}

func (s *Server) readFlowDDoSAssessment(ctx context.Context, actor *auth.Principal, settings ddosAssessmentSettings, at time.Time,
	retain func(context.Context, func(context.Context) error, func()) error) (flow.DDoSAssessment, error) {
	var empty flow.DDoSAssessment
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return empty, apierror.Unavailable("flow assessment cost policy is unavailable").Wrap(err)
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	ctx, flush := scopedABACDenial(ctx)
	var capture *reportFlowCapture
	retained := false
	release := func() {
		if capture != nil {
			capture.Close()
		}
		flush(s)
		cancel()
	}
	defer func() {
		if !retained {
			release()
		}
	}()
	windows, err := anomaly.DDoSCompletedWindows(at, settings.Input.PeriodSeconds)
	if err != nil {
		return empty, apierror.Validation("the assessment needs comparable completed UTC windows")
	}
	capture, err = s.captureDDoSWindows(ctx, actor, settings, ddosReferenceEnds(settings.Input.ReferenceWeeks(), windows), budget.MemoryBytes/4)
	if err != nil {
		return empty, err
	}
	if err := s.prepareDDoSApplication(ctx, actor, &settings); err != nil {
		return empty, err
	}
	selected, err := ddosMatchedWindows(ctx, capture, settings, budget.MemoryBytes/8, windows)
	if err != nil {
		return empty, mapDDoSCoverage(err)
	}
	match := selected[0]
	result, err := assessMatchedDDoS(ctx, capture, settings, match, budget.MemoryBytes/8)
	if err != nil {
		return empty, mapDDoSCoverage(err)
	}
	recheck := func(context.Context) error {
		if err := s.checkDDoSApplicationAccess(ctx, actor, settings); err != nil {
			return err
		}
		return s.recheckFlowEvidencePublication(ctx, actor, capture)
	}
	if retain != nil {
		if err := retain(ctx, recheck, release); err != nil {
			return empty, err
		}
		retained = true
	} else if err := recheck(ctx); err != nil {
		return empty, err
	}
	return result, ctx.Err()
}

func (s *Server) captureDDoSWindows(ctx context.Context, actor *auth.Principal, settings ddosAssessmentSettings, ends []time.Time, reserved int64) (*reportFlowCapture, error) {
	capture, err := s.captureFlowSourcesWithOptions(ctx, actor, []reportFlowSourceRef{settings.View}, true, true, reportFlowCaptureOptions{
		SeasonalPeriodEnds: ends, CombineSeasonal: true, DDoSAssessment: &settings, ReservedMemoryBytes: reserved,
	})
	if err != nil {
		return nil, err
	}
	if len(capture.Results) != len(ends) || !matchDDoSEvidenceClocks(capture.Inputs, settings, ends) {
		capture.Close()
		return nil, mapDDoSCoverage(anomaly.ErrDDoSCoverage)
	}
	return capture, nil
}

func matchDDoSEvidenceClocks(inputs []reportFlowInput, settings ddosAssessmentSettings, ends []time.Time) bool {
	return matchFlowEvidenceClocks(inputs, settings.View, ends, time.Duration(settings.Input.PeriodSeconds)*time.Second)
}

func mapDDoSCoverage(err error) error {
	if errors.Is(err, errDDoSCounterIntegrity) {
		return apierror.Conflict("the stored counters do not match the original flow and reported sampling rate").Wrap(err)
	}
	if errors.Is(err, errDDoSTrendCoverage) {
		return apierror.Conflict("volume growth follows the original weekly trend and needs independent corroboration").Wrap(err)
	}
	if errors.Is(err, anomaly.ErrDDoSMixedHistory) {
		return apierror.Conflict("missing historical transport, TCP flags or UDP ports leave mixed-vector growth inconclusive").Wrap(err)
	}
	if errors.Is(err, anomaly.ErrDDoSHistoricalClassification) {
		return apierror.Conflict("missing historical transport, TCP flags or UDP ports leave network vector growth inconclusive").Wrap(err)
	}
	if errors.Is(err, anomaly.ErrDDoSCurrentClassification) {
		return apierror.Conflict("missing current transport, TCP flags or UDP ports leave network pressure inconclusive").Wrap(err)
	}
	if errors.Is(err, errDDoSSampleCoverage) {
		return apierror.Conflict("a sampling group has fewer original flow records than the configured minimum").Wrap(err)
	}
	if errors.Is(err, anomaly.ErrDDoSRecordSupport) {
		return apierror.Conflict("a compared flow window has fewer original flow records than the configured minimum").Wrap(err)
	}
	if errors.Is(err, errDDoSTimingCoverage) {
		return apierror.Conflict("flow reports spanning the window boundary leave its traffic state unconfirmed").Wrap(err)
	}
	if errors.Is(err, errDDoSExporterSampling) {
		return apierror.Conflict("the observed exporters or their reported sampling rates differ between comparison windows").Wrap(err)
	}
	if errors.Is(err, errDDoSExporterCoverage) {
		return apierror.Conflict("a configured exporter has no stored observation in a required window").Wrap(err)
	}
	if errors.Is(err, anomaly.ErrDDoSCoverage) {
		return apierror.Conflict("the pinned source cannot prove comparable original flow observations").Wrap(err)
	}
	return err
}
