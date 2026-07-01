// SPDX-License-Identifier: LicenseRef-probectl-TBD

package govern

import (
	"strings"
	"testing"
)

func TestDataInventoryPrivacyGate(t *testing.T) {
	if errs := ValidateDataInventory(DataInventory()); len(errs) > 0 {
		var b strings.Builder
		for _, err := range errs {
			b.WriteString("\n  - " + err.Error())
		}
		t.Fatalf("data inventory privacy gate failed:%s", b.String())
	}
}

func TestDataInventoryCoversCoreStoreFamilies(t *testing.T) {
	required := []string{
		"audit-evidence",
		"ai-artifacts",
		"backups-snapshots",
		"device-endpoint-state",
		"ebpf-telemetry",
		"flow-telemetry",
		"identity-rbac-scim",
		"object-artifacts",
		"otlp-traces-logs",
		"path-topology",
		"probe-results",
		"shared-open-data",
		"siem-cursors",
	}
	got := map[string]DataInventoryEntry{}
	for _, entry := range DataInventory() {
		got[entry.ID] = entry
	}
	for _, id := range required {
		entry, ok := got[id]
		if !ok {
			t.Fatalf("data inventory missing required store family %q", id)
		}
		if len(entry.DataClasses) == 0 || entry.Retention == "" || entry.TenantDelete == "" {
			t.Fatalf("data inventory row %q lost required privacy semantics", id)
		}
	}
}

func TestDataInventoryReturnsDefensiveCopy(t *testing.T) {
	first := DataInventory()
	if len(first) == 0 {
		t.Fatal("inventory unexpectedly empty")
	}
	originalCategory := first[0].Categories[0]
	first[0].ID = "mutated"
	first[0].Categories[0] = CatCredential
	first[0].Processors[0] = "mutated"

	again := DataInventory()
	if again[0].ID == "mutated" || again[0].Processors[0] == "mutated" {
		t.Fatal("DataInventory must return a defensive copy")
	}
	if again[0].Categories[0] != originalCategory {
		t.Fatal("DataInventory must clone category slices")
	}
}
