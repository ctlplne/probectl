// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (b nativeMCPFlowBackend) CompareFlowViewFields(ctx context.Context, actor *auth.Principal, id string, input flow.FieldComparisonInput) (flow.FieldComparison, error) {
	if err := b.authorize(ctx, actor); err != nil {
		return flow.FieldComparison{}, err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	return b.server.readFlowFieldComparison(ctx, actor, fieldComparisonSettings(id, input), time.Now(), mcp.RetainNativePublication)
}

func (s *Server) readFlowFieldComparison(ctx context.Context, actor *auth.Principal, settings flowFieldComparisonSettings, at time.Time, retain func(context.Context, func(context.Context) error, func()) error) (flow.FieldComparison, error) {
	var out flow.FieldComparison
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return out, apierror.Unavailable("flow field comparison cost policy is unavailable").Wrap(err)
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	ctx, flush := scopedABACDenial(ctx)
	answer, capture, err := s.captureFlowFieldComparison(ctx, actor, settings, at, budget)
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
	if err != nil {
		return out, err
	}
	check := func(context.Context) error { return s.recheckFlowFieldPublication(ctx, actor, capture) }
	if retain != nil {
		if err := retain(ctx, check, release); err != nil {
			return out, err
		}
		retained = true
	} else if err := check(ctx); err != nil {
		return out, err
	}
	return answer, ctx.Err()
}

// captureFlowFieldComparison runs with a tenant query admission already held.
// The caller owns the returned capture until the source publication check.
func (s *Server) captureFlowFieldComparison(ctx context.Context, actor *auth.Principal, settings flowFieldComparisonSettings, at time.Time, budget flowstore.ExplorerBudget) (_ flow.FieldComparison, _ *reportFlowCapture, resultErr error) {
	var out flow.FieldComparison
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || tenant.String() != actor.TenantID {
		return out, nil, tenancy.ErrNoTenant
	}
	if settings.View.ID == "" || settings.View.Version != settings.Version {
		return out, nil, apierror.Validation("field comparison requires an exact saved query revision")
	}
	if err := settings.Validate(); err != nil {
		return out, nil, apierror.Validation(err.Error())
	}
	windows, err := anomaly.FlowFieldCompletedWindows(at, anomaly.FlowFieldComparisonCadence(settings.Cadence), settings.PeriodSeconds)
	if err != nil {
		return out, nil, apierror.Validation("the field comparison requires completed UTC windows")
	}
	capture, err := s.captureFlowSourcesWithOptions(ctx, actor, []reportFlowSourceRef{settings.View}, true, true, reportFlowCaptureOptions{
		SeasonalPeriodEnds:  windows.Ends(),
		CombineSeasonal:     windows.History.Samples > 0,
		ReservedMemoryBytes: budget.MemoryBytes / 4,
		FieldComparison:     &settings,
	})
	if err != nil {
		return out, nil, err
	}
	defer func() {
		if resultErr != nil {
			capture.Close()
		}
	}()
	if !matchFlowFieldInputClocks(capture.Inputs, settings, windows) {
		return out, nil, apierror.Conflict("flow source did not return all requested completed windows")
	}
	var answer flow.FieldComparison
	if windows.History.Samples > 0 {
		answer, err = compareHistoricalFlowFields(ctx, capture, settings, windows, budget.MemoryBytes/8)
	} else {
		answer, err = compareCapturedFlowFields(ctx, capture, settings, budget.MemoryBytes/8)
	}
	if errors.Is(err, anomaly.ErrFlowFieldCoverage) {
		return out, nil, apierror.Conflict("flow source cannot prove a complete comparable ranking").Wrap(err)
	}
	if err != nil {
		return out, nil, err
	}
	return answer, capture, ctx.Err()
}

// Complete source I/O before locking. A committed visibility, grant,
// vocabulary or source-generation change must win over the captured data.
func (s *Server) recheckFlowFieldPublication(ctx context.Context, actor *auth.Principal, capture *reportFlowCapture) error {
	return tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		return s.validateReportSourcePublication(store.WithReportSourceAuditLock(ctx, sc), sc, actor, capture)
	})
}

func matchFlowFieldInputClocks(inputs []reportFlowInput, settings flowFieldComparisonSettings, windows anomaly.FlowFieldComparisonClocks) bool {
	ends := windows.Ends()
	if len(inputs) != len(ends) {
		return false
	}
	length := windows.After.End.Sub(windows.After.Start)
	for i, input := range inputs {
		if input.ID != settings.View.ID || input.Version != settings.View.Version || input.Period != "current" ||
			!input.To.Equal(ends[i]) || !input.From.Equal(ends[i].Add(-length)) ||
			input.TagRevision != inputs[0].TagRevision || !input.TagAsOf.Equal(inputs[0].TagAsOf) {
			return false
		}
	}
	return true
}
