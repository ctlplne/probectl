// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestClientReportCapacityKeepsExplicitAssumptionsAndCalendarHorizon(t *testing.T) {
	from := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	definition := reporting.ClientReportCapacityTarget{Target: reporting.ClientReportCapacityRef{Kind: "interface", ContextID: "context", InterfaceID: "interface"}, Direction: "in", CapacityBPS: "12345678901234567890.125", MaximumPollGap: "7m", PhysicalBounds: []reporting.ClientReportPhysicalBound{{ContextID: "context", InterfaceID: "interface", MaxBPS: "18446744073709551615"}}}
	input, err := clientReportCapacityInput(definition, from, to)
	if err != nil || input.From != "2024-02-01T00:00:00Z" || input.To != "2024-03-01T00:00:00Z" || input.Until != "2024-04-01T00:00:00Z" || input.CapacityBPS != definition.CapacityBPS || input.PhysicalBounds[0].MaxBPS != definition.PhysicalBounds[0].MaxBPS || input.MaximumPollGap != "7m" {
		t.Fatal("monthly template replaced exact operator assumptions or calendar boundaries", err)
	}
	definition.ForecastMonths = -1
	if _, err := clientReportCapacityInput(definition, from, to); err == nil {
		t.Fatal("negative forecast horizon accepted")
	}
}

func TestClientReportCapacityPreservesInteractiveMFARequirement(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	server := &Server{requireMFA: true}
	remaining := int64(1 << 20)
	result, err := server.captureClientReportCapacity(ctx, &auth.Principal{TenantID: tenant, UserID: "owner"}, &clientReportCapture{TenantID: tenant}, []reporting.ClientReportCapacityTarget{{}}, flowstore.DefaultExplorerBudget(), &remaining)
	domain, ok := apierror.As(err)
	if !ok || domain.Kind != apierror.KindForbidden || result != nil {
		t.Fatal("monthly capacity bypassed required interactive MFA", err)
	}
}
