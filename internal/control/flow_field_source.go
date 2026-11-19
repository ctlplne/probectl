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
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || tenant.String() != actor.TenantID {
		return out, tenancy.ErrNoTenant
	}
	if err := settings.validate(); err != nil {
		return out, err
	}
	windows, err := anomaly.FlowFieldCompletedWindows(at, anomaly.FlowFieldComparisonCadence(settings.Cadence), settings.PeriodSeconds)
	if err != nil {
		return out, apierror.Validation("the field comparison requires completed UTC windows")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return out, apierror.Unavailable("flow field comparison cost policy is unavailable").Wrap(err)
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	ctx, flush := scopedABACDenial(ctx)
	capture, err := s.captureFlowSourcesWithOptions(ctx, actor, []reportFlowSourceRef{settings.View}, true, true, reportFlowCaptureOptions{
		SeasonalPeriodEnds:  []time.Time{windows.Before.End, windows.After.End},
		ReservedMemoryBytes: budget.MemoryBytes / 4,
		FieldComparison:     &settings,
	})
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
	if len(capture.Inputs) != 2 || !capture.Inputs[0].From.Equal(windows.Before.Start) || !capture.Inputs[0].To.Equal(windows.Before.End) ||
		!capture.Inputs[1].From.Equal(windows.After.Start) || !capture.Inputs[1].To.Equal(windows.After.End) {
		return out, apierror.Conflict("flow source did not return the complete requested window pair")
	}
	answer, err := compareCapturedFlowFields(ctx, capture, settings, budget.MemoryBytes/8)
	if errors.Is(err, anomaly.ErrFlowFieldCoverage) {
		return out, apierror.Conflict("flow source cannot prove a complete comparable ranking").Wrap(err)
	}
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
