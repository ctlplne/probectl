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

func TestIRIntegrityProofsStayGlobalAndEncryptedRecordsStayTenantOwned(t *testing.T) {
	global := []string{
		"ir_attribution_heads",
		"ir_key_shred_records",
		"ir_key_shred_heads",
		"ir_post_shred_attempt_records",
		"ir_post_shred_attempt_heads",
	}
	erased := ProviderOwnedTenantTables()
	for _, table := range global {
		if !ProviderOwnedTable(table) {
			t.Fatalf("%s must stay out of tenant silo schemas", table)
		}
		for _, candidate := range erased {
			if candidate == table {
				t.Fatalf("%s must survive provider-row erasure", table)
			}
		}
	}
	if ProviderOwnedTable("ir_attribution_records") {
		t.Fatal("encrypted IR attribution records must remain tenant-local/siloed")
	}

	filtered := FilterTenantOwned([]string{
		"audit_events",
		"ir_attribution_records",
		"ir_attribution_heads",
		"ir_key_shred_records",
		"ir_key_shred_heads",
		"ir_post_shred_attempt_records",
		"ir_post_shred_attempt_heads",
	})
	if len(filtered) != 2 ||
		filtered[0] != "audit_events" ||
		filtered[1] != "ir_attribution_records" {
		t.Fatalf(
			"tenant-owned IR filter = %v, want [audit_events ir_attribution_records]",
			filtered,
		)
	}
}
