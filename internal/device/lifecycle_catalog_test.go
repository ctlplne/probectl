// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeviceLifecycleUsesExactProductAndSourceDate(t *testing.T) {
	const source = `{
		"version": 1, "observed_at":"2026-11-21",
		"records":[{"manufacturer":"Example Networks","model":"EX-CHASSIS",
		 "notice_url":"https://example.invalid/notices/ex-chassis",
		 "notice_published_at":"2024-06-01","end_of_sale":"2025-12-12",
		 "end_of_security_fixes":"2027-10-12","end_of_support":"2028-12-12"}]
	}`
	catalog, err := readDeviceLifecycleCatalog(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 21, 6, 0, 0, 0, time.UTC)
	record, ok := catalog.lookup("Example Networks", "EX-CHASSIS", now, 24*time.Hour)
	if !ok || record.EndOfSale != "2025-12-12" || record.EndOfSecurityFixes != "2027-10-12" ||
		record.EndOfSupport != "2028-12-12" || !strings.HasSuffix(record.NoticeURL, "/ex-chassis") {
		t.Fatal("lifecycle milestones or source identity were lost", record)
	}
	for _, missing := range []string{"EX-CHASSIS-V2", "EX-CHASSI", ""} {
		if record, ok := catalog.lookup("Example Networks", missing, now, 24*time.Hour); ok || record != (deviceLifecycleRecord{}) {
			t.Fatal("an inferred product acquired published lifecycle evidence", record)
		}
	}
	if _, ok := catalog.lookup("Example Networks", "EX-CHASSIS", now.AddDate(0, 0, 2), 24*time.Hour); ok {
		t.Fatal("an expired snapshot became current device lifecycle evidence")
	}
	if _, ok := (*deviceLifecycleCatalog)(nil).lookup("Example Networks", "EX-CHASSIS", now, 24*time.Hour); ok {
		t.Fatal("a missing source claimed lifecycle coverage")
	}
	for _, invalid := range []string{
		strings.Replace(source, "https://", "http://", 1),
		strings.Replace(source, "2028-12-12", "invalid", 1),
		source + " {}",
	} {
		if _, err := readDeviceLifecycleCatalog(strings.NewReader(invalid)); !errors.Is(err, errDeviceLifecycleCatalog) {
			t.Fatal("accepted invalid lifecycle provenance or source shape", err)
		}
	}
}
