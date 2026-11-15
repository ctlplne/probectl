// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAssessmentFlowSampleDefinitionKeepsPortablePinnedSources(t *testing.T) {
	const source = "33333333-3333-4333-8333-333333333333"
	const destination = "44444444-4444-4444-8444-444444444444"
	end := time.Now().UTC().Add(-time.Hour)
	definition := dashboardDefinition{ClientReport: &reporting.ClientReportDefinition{Period: "assessment", Timezone: "UTC", Assessment: &reporting.ClientReportAssessment{From: end.AddDate(0, 0, -14).Format(time.RFC3339Nano), To: end.Format(time.RFC3339Nano), Preparer: "Example MSP"}, CapacityTargets: []reporting.ClientReportCapacityTarget{}},
		FlowSources: []reportFlowSourceRef{{ID: source, Version: "9007199254740993"}}, RedactionState: "current tenant policy", Provenance: []string{"selected sample"}, CoverageLimitations: []string{"not continuous coverage"}}
	if err := cleanDashboardDefinition(&definition); err != nil {
		t.Fatal("assessment refused its complete selected flow sample", err)
	}
	manifest := dashboardCreateToManifest(dashboardCreateRequest{Name: "Prospect sample", Preset: "operator", Definition: definition})
	raw, err := json.Marshal(manifest)
	if err != nil || bytes.Contains(raw, []byte(source)) || bytes.Contains(raw, []byte("9007199254740993")) || len(manifest.Spec.Definition.FlowSources) != 1 {
		t.Fatal("portable assessment retained a source tenant's query identity or lost the slot", err)
	}
	if _, err := dashboardManifestToCreateBound(manifest, nil); err == nil {
		t.Fatal("assessment import adopted the source query without a destination binding")
	}
	slot := manifest.Spec.Definition.FlowSources[0].Slot
	imported, err := dashboardManifestToCreateBound(manifest, map[string]reportFlowSourceRef{slot: {ID: destination, Version: "2"}})
	if err != nil || len(imported.Definition.FlowSources) != 1 || imported.Definition.FlowSources[0].ID != destination || imported.Definition.ClientReport.Assessment.To != definition.ClientReport.Assessment.To {
		t.Fatal("assessment sample did not preserve its exact window and destination binding", err)
	}
	definition.ClientReport = &reporting.ClientReportDefinition{Timezone: "UTC", CapacityTargets: []reporting.ClientReportCapacityTarget{}}
	if err := cleanClientReportDefinition(&definition); err == nil {
		t.Fatal("calendar reports silently adopted assessment-only flow composition")
	}
}

func TestAssessmentFlowRequirementsKeepBothCurrentBoundariesAndExactWindows(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		capture := reportRequirementsFixture(tenant)
		monthly := &clientReportSourceRequirements{Captured: true, Generation: 1, From: capture.Inputs[0].To.AddDate(0, 0, -14), To: capture.Inputs[0].To, InputsDigest: strings.Repeat("a", 64), Tests: []store.ReportTestRequirement{}, Bindings: []store.ReportSourceBinding{}}
		for _, permission := range []string{permTestRead, permIncidentRead, permChangeRead, "entities.read", "metrics.read"} {
			monthly.Access = append(monthly.Access, clientReportAccessRequirement{Permission: permission, Resource: map[string]string{auth.ResourceTenantKey: tenant}})
		}
		capture.Monthly = monthly
		raw, err := marshalReportSourceRequirements(ctx, capture)
		if err != nil || !bytes.Contains(raw, []byte(`"version":5`)) || bytes.Contains(raw, []byte(`"tables"`)) {
			t.Fatal("combined requirements lost a source or retained result rows", err)
		}
		stored, err := parseReportSourceRequirements(ctx, raw)
		if err != nil || stored.Monthly == nil || len(stored.Inputs) != 1 || !stored.Inputs[0].To.Equal(monthly.To) || stored.Monthly.Generation != monthly.Generation {
			t.Fatal("combined assessment requirements changed exact source lineage", err)
		}
		capture.Permissions = []string{permAIQuery}
		if _, err := marshalReportSourceRequirements(ctx, capture); err == nil {
			t.Fatal("assessment presence substituted for flow read authority")
		}
		capture.Permissions = stored.Permissions
		monthly.Access = monthly.Access[1:]
		if _, err := marshalReportSourceRequirements(ctx, capture); err == nil {
			t.Fatal("flow presence substituted for assessment source authority")
		}
		stored.Inputs[0].To = monthly.To.Add(time.Nanosecond)
		if err := validateAssessmentFlowWindows(monthly, stored.Inputs); err == nil {
			t.Fatal("sample escaped the exact assessment window")
		}
		foreign := tenancy.WithTenant(t.Context(), tenancy.ID("foreign"))
		if _, err := parseReportSourceRequirements(foreign, raw); err == nil {
			t.Fatal("combined receipt crossed its outer tenant boundary")
		}
	}
}
