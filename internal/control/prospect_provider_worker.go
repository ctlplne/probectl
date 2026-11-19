// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *DashboardReportSupervisor) providerProspectWakeups() <-chan prospectProviderRequest {
	if s.sourceServer == nil {
		return nil
	}
	return s.sourceServer.prospectProviderRequests
}

func (s *DashboardReportSupervisor) runProviderProspectRequest(ctx context.Context, input prospectProviderRequest) error {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(input.tenant))
	if err := s.sourceServer.currentReportTenant(ctx, input.tenant); err != nil {
		return err
	}
	var tenantName string
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := (store.ProspectEngagements{}).CurrentProviderRequest(ctx, sc, input.request.ID, input.request.EngagementRevision, input.request.AccessRevision)
		if err != nil || !current {
			return err
		}
		tenantName, err = dashboardTenantName(ctx, sc)
		return err
	})
	if err != nil || tenantName == "" {
		return err
	}
	return s.materializeProspectAssessmentWithRequest(ctx, input.tenant, tenantName, s.now().UTC(), &input.request)
}
