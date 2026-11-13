// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type scheduledReportAuthority struct {
	request *http.Request
	view    *store.DashboardView
	capture *reportFlowCapture
	cancel  context.CancelFunc
}

func (a *scheduledReportAuthority) close() {
	if a != nil {
		if a.capture != nil {
			a.capture.Close()
		}
		if a.cancel != nil {
			a.cancel()
		}
	}
}

// A write credential is not a source-read delegation. Prove every currently
// selected source/context capability before enabling work under future owner
// authority. No transaction spans source IO and no captured rows are stored.
func (s *Server) prepareScheduledReportAuthority(r *http.Request, dashboardID string) (*scheduledReportAuthority, error) {
	authority := &scheduledReportAuthority{request: r}
	var definition dashboardDefinition
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		authority.view, err = (store.DashboardReports{}).GetView(ctx, sc, dashboardID, dashboardActorID(r))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(authority.view.Definition, &definition); err != nil {
			return apierror.Internal("stored scheduled dashboard definition is invalid").Wrap(err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(definition.FlowSources) == 0 && definition.ClientReport == nil {
		return authority, nil
	}
	if err := cleanDashboardDefinition(&definition); err != nil {
		return nil, err
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, apierror.Unavailable("report schedule source policy is unavailable")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil {
		return nil, apierror.Unauthorized("authentication required")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID)), budget.ExecutionLimit)
	authority.cancel = cancel
	authority.request = r.WithContext(ctx)
	capture, err := s.captureConfiguredReportSources(ctx, actor, definition, time.Now().UTC())
	if err != nil {
		authority.close()
		return nil, reportGenerationError(err)
	}
	authority.capture = capture
	return authority, nil
}

func (s *Server) validateScheduledReportAuthority(ctx context.Context, sc tenancy.Scope, authority *scheduledReportAuthority) error {
	if authority == nil {
		return apierror.Forbidden("report schedule source authority is unavailable")
	}
	if authority.capture == nil {
		return nil
	}
	current, err := (store.DashboardReports{}).GetViewForReportPublication(ctx, sc, authority.view.ID, dashboardActorID(authority.request))
	if err != nil {
		return err
	}
	if !dashboardReportViewMatches(authority.view, current) {
		return apierror.Conflict("dashboard changed during schedule source preflight")
	}
	return s.validateReportSourcePublication(ctx, sc, auth.PrincipalFrom(authority.request.Context()), authority.capture)
}
