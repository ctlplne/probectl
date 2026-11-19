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
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ddosAssessmentSettings struct {
	View      reportFlowSourceRef
	Input     flow.DDoSAssessmentInput
	Target    netip.Prefix
	SideField string
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
	target, err := netip.ParsePrefix(input.Prefix)
	if err != nil || target != target.Masked() || target.Addr().Is4In6() {
		return empty, apierror.Validation("the protected prefix must be a canonical IPv4 or IPv6 prefix")
	}
	if _, err := flow.QueryViewVersion(input.Version); err != nil || !reportRequirementUUID(viewID) {
		return empty, apierror.Validation("the assessment needs an exact saved flow view revision")
	}
	var side string
	switch input.Direction {
	case "ingress":
		side = "dst_addr"
	case "egress":
		side = "src_addr"
	default:
		return empty, apierror.Validation("select the observed ingress or egress direction")
	}
	if input.PeriodSeconds != 60 && input.PeriodSeconds != 120 && input.PeriodSeconds != 300 {
		return empty, apierror.Validation("assessment windows must be 60, 120 or 300 seconds")
	}
	limits := input.Thresholds()
	if limits.Validate() != nil {
		return empty, apierror.Validation("set positive traffic and coverage floors and a valid growth and vector share")
	}
	return ddosAssessmentSettings{View: reportFlowSourceRef{ID: viewID, Version: input.Version}, Input: input, Target: target, SideField: side}, nil
}

func (settings ddosAssessmentSettings) preparePlan(plan *flow.QueryPlan) error {
	if plan.To.Sub(plan.From) != time.Duration(settings.Input.PeriodSeconds)*time.Second || plan.Cursor != "" {
		return apierror.Validation("the saved flow lookback must match the completed assessment window")
	}
	condition := flow.QueryPredicate{Field: settings.SideField, Op: flow.QueryCIDR, Values: []string{settings.Target.String()}}
	base := plan.Filter
	bound := &flow.QueryFilterGroup{Mode: "include", Match: "all", Conditions: []flow.QueryPredicate{condition}}
	if base != nil {
		if base.Mode == "include" && base.Match == "all" {
			bound = &flow.QueryFilterGroup{Mode: base.Mode, Match: base.Match, Groups: base.Groups, Saved: base.Saved,
				Conditions: append(slices.Clone(base.Conditions), condition)}
		} else {
			bound.Groups = []flow.QueryFilterGroup{*base}
		}
	}
	plan.Filter, plan.View, plan.DataSeries = bound, "table", "raw"
	plan.GroupBy, plan.MatrixWith = []string{settings.SideField, "transport", "tcp_flags", "src_port", "sampling"}, nil
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
	windows, err := anomaly.FlowFieldCompletedWindows(at, anomaly.FlowFieldPreviousWeek, settings.Input.PeriodSeconds)
	if err != nil {
		return empty, apierror.Validation("the assessment needs comparable completed UTC windows")
	}
	capture, err = s.captureFlowSourcesWithOptions(ctx, actor, []reportFlowSourceRef{settings.View}, true, true, reportFlowCaptureOptions{
		SeasonalPeriodEnds: windows.Ends(), CombineSeasonal: true, DDoSAssessment: &settings, ReservedMemoryBytes: budget.MemoryBytes / 4,
	})
	if err != nil {
		return empty, err
	}
	result, err := assessCapturedDDoS(ctx, capture, settings, windows, budget.MemoryBytes/8)
	if errors.Is(err, anomaly.ErrDDoSCoverage) {
		return empty, apierror.Conflict("the pinned source cannot prove comparable original flow observations").Wrap(err)
	}
	if err != nil {
		return empty, err
	}
	recheck := func(context.Context) error { return s.recheckFlowEvidencePublication(ctx, actor, capture) }
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
