// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

func TestReportInboxCursorOnlySelectsCurrentTenantAndOwnerPosition(t *testing.T) {
	position := store.ReportArtifactPosition{GeneratedAt: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), ID: "already-visible-id"}
	cursor, err := encodeReportInboxCursor("tenant-a", "owner-a", position)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"limit": {"501"}, "cursor": {cursor}}
	limit, decoded, err := parseReportInboxPage(query, "tenant-a", "owner-a", 1<<20)
	if err != nil || limit != 501 || decoded == nil || *decoded != position {
		t.Fatal("inbox cursor narrowed full page or changed visible position", err)
	}
	for _, identity := range [][2]string{{"tenant-b", "owner-a"}, {"tenant-a", "owner-b"}} {
		if _, _, err := parseReportInboxPage(query, identity[0], identity[1], 1<<20); err == nil {
			t.Fatal("inbox cursor became a tenant or owner grant")
		}
	}
	for _, bad := range []url.Values{
		{"limit": {"0"}}, {"limit": {"-1"}}, {"limit": {"2147483647"}}, {"limit": {"1", "2"}},
		{"tenant_id": {"tenant-b"}}, {"cursor": {"not-a-cursor"}}, {"cursor": {""}},
		{"cursor": {base64.RawURLEncoding.EncodeToString([]byte(`{"version":1,"version":1}`))}},
	} {
		if _, _, err := parseReportInboxPage(bad, "tenant-a", "owner-a", 1<<20); err == nil {
			t.Fatal("invalid inbox position/shape was admitted", bad)
		}
	}
	if _, _, err := parseReportInboxPage(query, "tenant-a", "owner-a", 1); err == nil {
		t.Fatal("cursor decode ignored finite operation memory")
	}
}
