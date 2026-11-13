// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"testing"
	"time"
)

func TestClientReportMonthUsesCompleteUTCCalendarBounds(t *testing.T) {
	for _, tc := range []struct {
		month, at, from, to string
	}{
		{"2024-02", "2024-03-01T00:00:00Z", "2024-02-01", "2024-03-01"},
		{"2025-02", "2025-03-01T00:00:00Z", "2025-02-01", "2025-03-01"},
		{"2025-12", "2026-01-01T00:00:00Z", "2025-12-01", "2026-01-01"},
		{"", "2026-11-01T00:00:00+05:30", "2026-09-01", "2026-10-01"},
	} {
		at, err := time.Parse(time.RFC3339, tc.at)
		if err != nil {
			t.Fatal(err)
		}
		from, to, err := ClientReportMonth(tc.month, at)
		if err != nil || from.Format(time.DateOnly) != tc.from || to.Format(time.DateOnly) != tc.to || from.Location() != time.UTC || to.Location() != time.UTC {
			t.Fatal("calendar month lost exact UTC bounds", tc.month, from, to, err)
		}
	}
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	for _, month := range []string{"2026-11", "2026-12", "2026-2", "2026-02-01", "0000-01", " 2026-10", "2026-13"} {
		if _, _, err := ClientReportMonth(month, at); err == nil {
			t.Fatal("incomplete or noncanonical monthly report was accepted", month)
		}
	}
}

func TestClientReportPeriodUsesCivilCalendarAndLabelsPartial(t *testing.T) {
	for _, tc := range []struct {
		zone, month, kind, at, from, to string
		partial                         bool
	}{
		{"America/New_York", "2024-03", "completed_month", "2024-04-01T04:00:00Z", "2024-03-01T05:00:00Z", "2024-04-01T04:00:00Z", false},
		{"Asia/Kolkata", "", "completed_month", "2026-11-01T00:15:00+05:30", "2026-09-30T18:30:00Z", "2026-10-31T18:30:00Z", false},
		{"America/Asuncion", "2017-10", "completed_month", "2017-11-02T00:00:00Z", "2017-10-01T04:00:00Z", "2017-11-01T03:00:00Z", false},
		{"Asia/Kolkata", "", "month_to_date", "2026-11-14T12:34:00+05:30", "2026-10-31T18:30:00Z", "2026-11-14T07:04:00Z", true},
		{"UTC", "2024-02", "completed_month", "2024-03-01T00:00:00Z", "2024-02-01T00:00:00Z", "2024-03-01T00:00:00Z", false},
	} {
		at, err := time.Parse(time.RFC3339, tc.at)
		if err != nil {
			t.Fatal(err)
		}
		period, err := ResolveClientReportPeriod(t.Context(), ClientReportDefinition{Month: tc.month, Timezone: tc.zone, Period: tc.kind}, at)
		if err != nil || period.From.Format(time.RFC3339) != tc.from || period.To.Format(time.RFC3339) != tc.to || period.Partial != tc.partial || period.Timezone != tc.zone || period.Kind != tc.kind {
			t.Fatalf("civil report period %s/%s: %+v %v", tc.zone, tc.month, period, err)
		}
	}
}
