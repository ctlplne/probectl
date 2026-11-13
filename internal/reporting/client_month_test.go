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
