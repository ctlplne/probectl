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

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("docslint: read %s: %v", rel, err)
	}
	return string(b)
}

// TestGeneratedOpenAPIHasCurrentAuthModel prevents the public integration
// contract from drifting back to sprint-era auth prose. DOCS-001: the shipped
// control-plane spec used to say tenant identity was a dev stub and real
// SSO/SCIM identity would land later, even though sessions, OIDC, tenant-first
// authorization, RBAC, and ABAC are wired in the default served path.
func TestGeneratedOpenAPIHasCurrentAuthModel(t *testing.T) {
	banned := []string{
		"dev stub",
		"Dev stub",
		"S9",
		"lands in S18",
		"real identity",
	}
	mustContain := []string{
		"authenticated session/OIDC principal",
		"tenant boundary before RBAC/ABAC",
		"release binaries do not accept it as an identity source",
	}

	for _, rel := range []string{"internal/control/openapi.json", "ee/provider/openapi.json"} {
		body := readRepoFile(t, rel)
		for _, phrase := range banned {
			if strings.Contains(body, phrase) {
				t.Errorf("%s still contains stale sprint-era auth wording %q (DOCS-001)", rel, phrase)
			}
		}
		if rel == "internal/control/openapi.json" {
			for _, want := range mustContain {
				if !strings.Contains(body, want) {
					t.Errorf("%s missing current auth-model wording %q (DOCS-001)", rel, want)
				}
			}
		}
	}
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
	if !strings.Contains(doc, "Postgres (metadata)") || !strings.Contains(doc, "ClickHouse (telemetry)") {
		t.Errorf("multi-region.md RPO table must distinguish metadata (Postgres) from telemetry (ClickHouse)")
	}
}

// TestDR_TelemetryRPOIsExplicit asserts dr.md states the telemetry-store RPO
// explicitly rather than vaguely deferring to "replication and backups".
func TestDR_TelemetryRPOIsExplicit(t *testing.T) {
	doc := readDoc(t, "ops/dr.md")
	if !strings.Contains(doc, "≤ 24 h") {
		t.Errorf("dr.md must state the telemetry-store regional RPO explicitly (≤ 24 h with the shipped profile)")
	}
	if !strings.Contains(doc, "does **not**\nreplicate") && !strings.Contains(doc, "does **not** replicate") {
		// allow either wrapped form
		if !strings.Contains(strings.ReplaceAll(doc, "\n", " "), "does **not** replicate") {
			t.Errorf("dr.md must state ClickHouse does not replicate cross-region by default")
		}
	}
}

func TestTelemetryDRProfileIsDocumentedAndDrilled(t *testing.T) {
	backupDoc := readDoc(t, "ops/backup-restore.md")
	multiRegionDoc := readDoc(t, "multi-region.md")
	values := readRepoFile(t, "deploy/helm/probectl/values.yaml")
	drill := readRepoFile(t, "scripts/backup_restore_drill.sh")

	for _, want := range []string{
		"Telemetry regional DR profile: off-region ClickHouse backups",
		"Default RPO",
		"≤ 24 h",
		"tenant_id",
		"off-box artifact",
	} {
		if !strings.Contains(backupDoc, want) {
			t.Errorf("backup-restore.md must document the default telemetry DR profile detail %q", want)
		}
	}
	for _, want := range []string{
		"≤ 24 h",
		"backup.clickhouse.schedule",
		"backup-drill",
	} {
		if !strings.Contains(multiRegionDoc, want) {
			t.Errorf("multi-region.md must surface the shipped telemetry RPO/profile detail %q", want)
		}
	}
	for _, want := range []string{"Telemetry regional DR profile", "ClickHouse telemetry RPO is <=24h", "off-region storage"} {
		if !strings.Contains(values, want) {
			t.Errorf("Helm values must describe the shipped ClickHouse telemetry DR profile detail %q", want)
		}
	}
	for _, want := range []string{"tenant_id", "CH_OTHER_TENANT", "clickhouse regional-loss drill: PASS"} {
		if !strings.Contains(drill, want) {
			t.Errorf("backup_restore_drill.sh must prove tenant-scoped ClickHouse regional recovery detail %q", want)
		}
	}
}

// TestOTLPExportContractDocumentsAllSignals keeps the operator-facing docs in
// lockstep with the shipped OTLP export wiring. ARCH-002: the old docs said
// export was metrics-only while the control plane forwarded traces and logs too,
// which is a bad surprise because traces/logs can be sensitive tenant telemetry.
func TestOTLPExportContractDocumentsAllSignals(t *testing.T) {
	otlpDoc := readDoc(t, "otlp.md")
	configDoc := readDoc(t, "configuration.md")
	mainGo := readRepoFile(t, "cmd/probectl-control/main.go")
	buildersGo := readRepoFile(t, "cmd/probectl-control/builders.go")
	exportGo := readRepoFile(t, "internal/pipeline/otlpexport.go")

	banned := []string{
		"OTLP export. " + "Metrics only",
		"Re-exporting ingested traces/logs " + "is not a goal",
		"probectl's own signals are " + "metric-shaped",
		"replaying other systems'\n  " +
			"traces/logs back out",
	}
	for _, phrase := range banned {
		if strings.Contains(otlpDoc, phrase) || strings.Contains(configDoc, phrase) {
			t.Errorf("OTLP docs still contain stale metrics-only export claim %q", phrase)
		}
	}

	docMustContain := []string{
		"metrics, traces, and logs",
		"PROBECTL_OTLP_EXPORT_ENDPOINT",
		"remote export is encrypted",
	}
	for _, want := range docMustContain {
		if !strings.Contains(otlpDoc, want) {
			t.Errorf("docs/otlp.md must disclose all-signal OTLP export detail %q", want)
		}
	}
	if !strings.Contains(configDoc, "All three signals are\nforwarded") {
		t.Errorf("docs/configuration.md must document that OTLP export forwards metrics, traces, and logs")
	}

	codeMustContain := []string{
		"NewOTLPExportConsumer",
		"NewOTLPTraceExportConsumer",
		"NewOTLPLogExportConsumer",
		"otlp export enabled (metrics+traces+logs)",
	}
	code := mainGo + "\n" + buildersGo + "\n" + exportGo
	for _, want := range codeMustContain {
		if !strings.Contains(code, want) {
			t.Errorf("OTLP export code no longer wires all-signal export consumer %q", want)
		}
	}
}

// TestNoStaleScaffoldPlaceholders asserts that no package doc.go still carries
// the S0 "intentionally empty placeholder / carries no logic yet" boilerplate
// (DOCS-002). Those packages now ship real implementations, so the placeholder
// claim is an over-claim-in-reverse and must not return. Walks internal/ and
// ee/ for any doc.go containing the stale phrasing.
func TestNoStaleScaffoldPlaceholders(t *testing.T) {
	root := repoRoot(t)
	banned := []string{
		"intentionally empty placeholder",
		"carries no logic yet",
		"S0 scaffold",
	}
	for _, tree := range []string{"internal", "ee"} {
		base := filepath.Join(root, tree)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || filepath.Base(path) != "doc.go" {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			body := string(b)
			for _, phrase := range banned {
				if strings.Contains(body, phrase) {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s still carries stale scaffold phrasing %q — the package ships real logic now (DOCS-002)", rel, phrase)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("docslint: walk %s: %v", tree, err)
		}
	}
}
