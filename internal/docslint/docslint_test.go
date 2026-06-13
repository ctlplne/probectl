// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package docslint holds doc-accuracy tests: assertions that the operations
// docs do not over-claim capabilities the code does not ship. RESIL-003: the
// multi-region doc previously said tenant data "converges in the replicated
// stores", implying the telemetry store (ClickHouse) replicates cross-region
// like Postgres — it does not (single-node MergeTree by default). These tests
// fail if that over-claim returns or if the metadata-vs-telemetry RPO
// distinction is dropped.
package docslint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working dir to the module root (the dir
// holding go.mod), so the test is robust to where `go test` is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("docslint: could not locate go.mod from working dir")
		}
		dir = parent
	}
}

func readDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", rel))
	if err != nil {
		t.Fatalf("docslint: read %s: %v", rel, err)
	}
	return string(b)
}

// TestMultiRegion_NoTelemetryReplicationOverclaim asserts the multi-region doc
// does not claim telemetry "converges in the replicated stores" (the false
// claim that triggered RESIL-003) and that it explicitly distinguishes the
// metadata RPO from the telemetry (backup-cadence) RPO.
func TestMultiRegion_NoTelemetryReplicationOverclaim(t *testing.T) {
	doc := readDoc(t, "multi-region.md")

	// The exact over-claim must be gone.
	if strings.Contains(doc, "converges in the replicated stores") {
		t.Errorf("multi-region.md still over-claims telemetry replication " +
			"(\"converges in the replicated stores\") — ClickHouse is single-node MergeTree by default")
	}

	// The doc must now disclose the asymmetry: the telemetry store does NOT
	// replicate cross-region by default and its RPO is the backup cadence.
	mustContain := []string{
		"single-node",         // honest description of the default CH topology
		"backup cadence",      // the telemetry RPO
		"asymmetry",           // the section naming the gap
		"ReplicatedMergeTree", // the operator opt-in path
	}
	for _, want := range mustContain {
		if !strings.Contains(doc, want) {
			t.Errorf("multi-region.md missing required RPO-asymmetry disclosure %q", want)
		}
	}

	// The RPO table must distinguish the two stores.
	if !(strings.Contains(doc, "Postgres (metadata)") && strings.Contains(doc, "ClickHouse (telemetry)")) {
		t.Errorf("multi-region.md RPO table must distinguish metadata (Postgres) from telemetry (ClickHouse)")
	}
}

// TestDR_TelemetryRPOIsExplicit asserts dr.md states the telemetry-store RPO
// explicitly rather than vaguely deferring to "replication and backups".
func TestDR_TelemetryRPOIsExplicit(t *testing.T) {
	doc := readDoc(t, "ops/dr.md")
	if !strings.Contains(doc, "backup cadence") {
		t.Errorf("dr.md must state the telemetry-store regional RPO explicitly (backup cadence)")
	}
	if !strings.Contains(doc, "does **not**\nreplicate") && !strings.Contains(doc, "does **not** replicate") {
		// allow either wrapped form
		if !strings.Contains(strings.ReplaceAll(doc, "\n", " "), "does **not** replicate") {
			t.Errorf("dr.md must state ClickHouse does not replicate cross-region by default")
		}
	}
}
