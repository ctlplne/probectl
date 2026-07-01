// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
)

// liveCHMigrations is the LIVE migration set of every ClickHouse telemetry
// store — the same lists the stores apply at boot. The gate runs over THESE so
// a destructive change to any of flow/eBPF/OTLP/path reddens the build
// (SCHEMA-001 — these stores were previously outside the expand/contract gate).
func liveCHMigrations() map[string][]chmigrate.Migration {
	return map[string][]chmigrate.Migration{
		"flowstore": flowstore.CHMigrations(),
		"ebpfstore": ebpfstore.CHMigrations(),
		"otelstore": otelstore.CHMigrations(),
		"pathstore": pathstore.CHMigrations(),
	}
}

// TestClickHouseMigrationGate is the SCHEMA-001 migration-gate for the
// ClickHouse stores: every store's shipped chMigrations() must pass the
// destructive-DDL check. The known data-preserving rebuilds (flow/otel) and the
// re-discoverable-cache discard (path) carry the typed Destructive+Justification
// annotation and so pass; any UNannotated DROP/RENAME on a telemetry store fails.
func TestClickHouseMigrationGate(t *testing.T) {
	v := chmigrate.CheckAll(liveCHMigrations())
	if len(v) > 0 {
		var b strings.Builder
		for _, x := range v {
			b.WriteString("\n  " + x.String())
		}
		t.Fatalf("ClickHouse migrations break the destructive-DDL gate:%s", b.String())
	}
}

// goldenCHChecksums pins the Checksum() of every SHIPPED ClickHouse migration
// (SCHEMA-007). chmigrate enforces checksum-immutability only at APPLY time on a
// POPULATED ledger; a fresh-install edit to a shipped statement is caught by no
// integration test. This OFFLINE golden assertion fails the build the moment a
// shipped chMigrations() statement is edited — add a NEW version instead. When a
// version is legitimately added, append its entry here (the dump is in the test
// log on mismatch).
var goldenCHChecksums = map[string]string{
	"ebpfstore|1": "aa012aac6d4d404946fdd39def7560d56b3943bfd8f0b191fc793519c04a80e9",
	"flowstore|1": "875071f5ce661cb0cd28321315d4eff9ea89081c1c5795165b4049bad28d27db",
	"flowstore|2": "026b57e815a6cbcd0ee70cd6b000f339846573305cd75dc57de7735db2ea4855",
	"flowstore|3": "8d57cd291e20bfb21ef07200fb5cbc71c7f6d92ba290d64a3d659158c3c62e76",
	"otelstore|1": "386721d17bf79ac6ddd91eb798f920fdf28ce4d0c80919a44055a3922569acd0",
	"otelstore|2": "c7eddbb7f304453dfe47a5f53398d2346da81d190cf892732780ece08ff28a67",
	"pathstore|1": "487d228b1b871ef223a377bb47e8621a61e56e8f2f9ef3469490c66061ff8b42",
	"pathstore|2": "53f0f1079adfc037e3e481d3397a523a2e8049c79be9fbef87b7edcff964a76f",
	"pathstore|3": "279b7a534d9247afe2a82e9ae49182158d656f44dceac628861e034cfaa54f41",
}

// TestClickHouseMigrationChecksumsAreImmutable: SCHEMA-007. Editing any shipped
// statement changes its Checksum() and reddens this OFFLINE test — closing the
// fresh-install edit gap that the apply-time drift check (populated ledger only)
// leaves open.
func TestClickHouseMigrationChecksumsAreImmutable(t *testing.T) {
	got := map[string]string{}
	for comp, ms := range liveCHMigrations() {
		for _, m := range ms {
			got[comp+"|"+strconv.Itoa(m.Version)] = chmigrate.Checksum(m)
		}
	}
	if len(got) != len(goldenCHChecksums) {
		t.Fatalf("migration count changed: got %d, golden %d — update goldenCHChecksums (dump: %v)", len(got), len(goldenCHChecksums), got)
	}
	for key, want := range goldenCHChecksums {
		if g, ok := got[key]; !ok {
			t.Errorf("shipped migration %s is missing (renumbered/removed?) — shipped versions are immutable", key)
		} else if g != want {
			t.Errorf("migration %s checksum drift: golden %s, code %s — DO NOT edit a shipped migration; add a new version", key, want, g)
		}
	}
}

// TestClickHouseMigrationGateCatchesInjectedDestructive proves the gate is not
// vacuous: injecting an UNannotated DROP TABLE into a store's live list (as a
// future bad migration would) must be flagged. This is the acceptance test —
// "add a destructive statement to a store's chMigrations() and confirm the gate
// fails" — exercised against the real list rather than a synthetic one.
func TestClickHouseMigrationGateCatchesInjectedDestructive(t *testing.T) {
	sets := liveCHMigrations()
	flows := sets["flowstore"]
	// Append a hypothetical bad v99 that DROPs a telemetry table with no annotation.
	flows = append(flows, chmigrate.Migration{
		Version: 99, Name: "drop_flows_oops",
		Statements: []string{"DROP TABLE probectl_flows"},
	})
	sets["flowstore"] = flows

	v := chmigrate.CheckAll(sets)
	if len(v) == 0 {
		t.Fatal("gate must flag an unannotated DROP TABLE injected into flowstore's migrations")
	}
	found := false
	for _, x := range v {
		if x.Component == "flowstore" && x.Version == 99 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the injected flowstore v99 DROP to be flagged, got %v", v)
	}
}
