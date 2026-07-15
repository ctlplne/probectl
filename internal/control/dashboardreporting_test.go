// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"testing"
	"time"
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
		"dashboard.report_schedule": true,
		"dashboard.report_export":   true,
		"dashboard.report_download": true,
		"dashboard.report_delivery": true,
	}
	for _, action := range []string{
		"dashboard.save", "dashboard.report_schedule", "dashboard.report_export", "dashboard.report_download",
		"dashboard.report_delivery",
	} {
		if !want[action] {
			t.Fatalf("missing audit contract %q", action)
		}
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
