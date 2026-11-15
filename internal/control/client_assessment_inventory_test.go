// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAssessmentInventoryProjectionKeepsFrozenTenantMetadataAndPermissionRequirements(t *testing.T) {
	const contextID = "33333333-3333-4333-8333-333333333333"
	const entityID = "44444444-4444-4444-8444-444444444444"
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		from, to, _, _ := clientReportTableFixture(tenant)
		at := to.Add(14 * 24 * time.Hour)
		capture := &clientReportCapture{TenantID: tenant, From: from, To: to, InventoryAt: at,
			Inventory: []store.ClientReportInventoryItem{{Context: entity.ContextRecord{TenantID: tenant, ContextID: contextID, SiteLabel: "東京 site", VRFLabel: "customer VRF"},
				Entity: entity.Record{Scope: entity.Scope{TenantID: tenant, ContextID: contextID}, ID: entityID, Kind: entity.Device, Label: "tenant device", CreatedAt: from, UpdatedAt: to}}}}
		table, err := projectAssessmentInventory(ctx, capture, 1<<20)
		if err != nil || table.ExpectedRows != 1 {
			t.Fatal("complete assessment inventory was lost", err)
		}
		refs := assessmentInventoryRefs(capture.Inventory)
		access := []clientReportAccessRequirement{{Permission: "entities.read", Resource: map[string]string{auth.ResourceTenantKey: tenant, "context_id": contextID, "entity_id": entityID}}}
		if err := validateAssessmentInventoryRequirements(refs, access); err != nil {
			t.Fatal("valid canonical inventory requirements refused", err)
		}
		capture.Inventory[0].Entity.Label = "later mutable registry label"
		if err := table.WalkRows(ctx, func(row []string) error {
			if row[0] != tenant || row[4] != "東京 site" || row[8] != "tenant device" || row[13] != at.Format(time.RFC3339Nano) {
				t.Fatal("inventory borrowed mutable/foreign metadata or claimed the selected historical interval as its capture clock")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		foreign := tenancy.WithTenant(t.Context(), tenancy.ID("foreign"))
		called := false
		if err := table.WalkRows(foreign, func([]string) error { called = true; return nil }); !errors.Is(err, entity.ErrScopeMismatch) || called {
			t.Fatal("inventory cursor disclosed another tenant's metadata", err)
		}
		if err := validateAssessmentInventoryRequirements(refs, nil); err == nil {
			t.Fatal("retained inventory omitted its current entity permission requirement")
		}
		refs[0].EntityID = contextID
		if err := validateAssessmentInventoryRequirements(refs, access); err == nil {
			t.Fatal("another entity borrowed a captured inventory permission requirement")
		}
		capture.Inventory[0].Context.TenantID = "foreign"
		if _, err := projectAssessmentInventory(ctx, capture, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) {
			t.Fatal("mixed-tenant inventory entered a report", err)
		}
	}
}
