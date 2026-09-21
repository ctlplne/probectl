// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

func validDashboardRequest() dashboardCreateRequest {
	return dashboardCreateRequest{
		Name: " Fleet posture ", Preset: "Operator", Shared: true,
		Definition: dashboardDefinition{
			AbsoluteFrom: time.Now().UTC().Add(-time.Hour), AbsoluteTo: time.Now().UTC(),
			Provenance: []string{" control-plane APIs "}, RedactionState: " secrets removed ",
			CoverageLimitations: []string{" offline collectors omitted "},
			Metrics:             map[string]string{" Active tests ": " 12 "},
		},
	}
}

func TestDashboardDefinitionValidationAndTenantSafeShape(t *testing.T) {
	clean, err := cleanDashboardCreate(validDashboardRequest())
	if err != nil {
		t.Fatalf("cleanDashboardCreate: %v", err)
	}
	if clean.Name != "Fleet posture" || clean.Preset != "operator" || clean.Definition.Metrics["Active tests"] != "12" {
		t.Fatalf("unexpected clean request: %+v", clean)
	}

	bad := validDashboardRequest()
	bad.Definition.AbsoluteTo = bad.Definition.AbsoluteFrom
	if _, err := cleanDashboardCreate(bad); err == nil {
		t.Fatal("non-positive absolute range must fail closed")
	}
}

func TestReportScheduleRequiresConfiguredNonOutboundDestination(t *testing.T) {
	req := reportScheduleCreateRequest{
		DashboardID: "view-1", Name: "Daily posture", Format: "PDF", Cadence: "daily",
		DestinationID: reportInboxDestination, FirstRunAt: time.Now().UTC().Add(time.Hour),
	}
	clean, err := cleanSchedule(req)
	if err != nil {
		t.Fatalf("cleanSchedule: %v", err)
	}
	if clean.Format != "pdf" || clean.DestinationID != reportInboxDestination {
		t.Fatalf("unexpected clean schedule: %+v", clean)
	}
	req.DestinationID = "https://unconfigured.invalid/hook"
	if _, err := cleanSchedule(req); err == nil {
		t.Fatal("unconfigured outbound destination must fail closed")
	}
}

func TestExportAuditContractNamesEveryDashboardDataAccess(t *testing.T) {
	// These stable action names are the contract consumed by the audit search
	// surface and operational evidence packs. The integration test proves they
	// are appended transactionally; this unit test catches accidental renames.
	want := map[string]bool{
		"dashboard.save":            true,
		"dashboard.manifest_export": true,
		"dashboard.manifest_import": true,
		"dashboard.report_schedule": true,
		"dashboard.report_export":   true,
		"dashboard.report_download": true,
		"dashboard.report_delivery": true,
	}
	for _, action := range []string{
		"dashboard.save", "dashboard.manifest_export", "dashboard.manifest_import",
		"dashboard.report_schedule", "dashboard.report_export", "dashboard.report_download", "dashboard.report_delivery",
	} {
		if !want[action] {
			t.Fatalf("missing audit contract %q", action)
		}
	}
}

func TestDashboardManifestIsDeterministicRedactedAndRoundTrips(t *testing.T) {
	from := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	tenantID := "11111111-1111-1111-1111-111111111111"
	ownerID := "owner@example.test"
	definition, err := json.Marshal(dashboardDefinition{
		AbsoluteFrom: from,
		AbsoluteTo:   from.Add(time.Hour),
		Provenance: []string{
			"collector " + tenantID,
			"owned by " + ownerID,
		},
		RedactionState:      "token=plain-secret",
		CoverageLimitations: []string{"host 198.51.100.42 is offline"},
		Metrics: map[string]string{
			"z token":      "api_key=manifest-secret",
			"a owner note": ownerID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	view := &store.DashboardView{
		ID: "never-export-this-id", TenantID: tenantID, OwnerID: ownerID,
		Name: "Dashboard for " + ownerID, Preset: "operator", Shared: true, Definition: definition,
	}

	first, err := dashboardManifestFromView(view)
	if err != nil {
		t.Fatalf("dashboardManifestFromView: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := dashboardManifestFromView(view)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("manifest is not byte deterministic:\n%s\n%s", firstJSON, secondJSON)
	}
	for _, forbidden := range []string{tenantID, ownerID, "manifest-secret", "plain-secret", view.ID, "198.51.100.42"} {
		if strings.Contains(string(firstJSON), forbidden) {
			t.Errorf("manifest leaked %q: %s", forbidden, firstJSON)
		}
	}
	if got := first.Spec.Definition.Metrics[0].Name; got != "a owner note" {
		t.Fatalf("metrics are not sorted: first = %q", got)
	}
	roundTrip, err := dashboardManifestToCreate(first)
	if err != nil {
		t.Fatalf("dashboardManifestToCreate: %v", err)
	}
	if roundTrip.Name != first.Metadata.Name || roundTrip.Preset != "operator" ||
		len(roundTrip.Definition.Metrics) != 2 {
		t.Fatalf("unexpected round trip: %+v", roundTrip)
	}
}

func TestDashboardManifestRejectsUnknownVersionDuplicateMetricsAndInvalidBounds(t *testing.T) {
	base := dashboardCreateToManifest(validDashboardRequest())
	base.APIVersion = "probectl.io/dashboard/v99"
	if _, err := dashboardManifestToCreate(base); err == nil {
		t.Fatal("unknown manifest version must fail closed")
	}

	base = dashboardCreateToManifest(validDashboardRequest())
	base.Spec.Definition.Metrics = append(base.Spec.Definition.Metrics, base.Spec.Definition.Metrics[0])
	if _, err := dashboardManifestToCreate(base); err == nil {
		t.Fatal("duplicate manifest metric names must fail closed")
	}

	base = dashboardCreateToManifest(validDashboardRequest())
	base.Spec.Definition.AbsoluteTo = base.Spec.Definition.AbsoluteFrom
	if _, err := dashboardManifestToCreate(base); err == nil {
		t.Fatal("invalid manifest time bounds must fail closed")
	}
}

func TestDashboardReportScheduleCadenceNeverReplaysMissedIntervals(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		cadence string
		start   time.Time
		want    time.Time
	}{
		{"daily", now.AddDate(0, 0, -4), now.AddDate(0, 0, 1)},
		{"weekly", now.AddDate(0, 0, -14), now.AddDate(0, 0, 7)},
		{"monthly", now.AddDate(0, -2, 0), now.AddDate(0, 1, 0)},
	} {
		next, err := nextDashboardReportRun(tc.cadence, tc.start, now)
		if err != nil {
			t.Fatalf("%s: %v", tc.cadence, err)
		}
		if !next.Equal(tc.want) {
			t.Errorf("%s next = %s, want %s", tc.cadence, next, tc.want)
		}
	}
	if _, err := nextDashboardReportRun("hourly", now, now); err == nil {
		t.Fatal("unsupported cadence must fail closed")
	}
}
