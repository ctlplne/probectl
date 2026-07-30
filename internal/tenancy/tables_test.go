// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenancy

import "testing"

func TestAuditStreamHeadsStayGlobalAndOutOfTenantEraseList(t *testing.T) {
	const table = "audit_stream_heads"
	if !ProviderOwnedTable(table) {
		t.Fatal("audit stream heads must stay out of tenant silo schemas")
	}
	for _, candidate := range ProviderOwnedTenantTables() {
		if candidate == table {
			t.Fatal("retained audit stream heads must stay out of provider-row erasure")
		}
	}

	filtered := FilterTenantOwned([]string{"audit_events", table})
	if len(filtered) != 1 || filtered[0] != "audit_events" {
		t.Fatalf("tenant-owned filter = %v, want [audit_events]", filtered)
	}
}
