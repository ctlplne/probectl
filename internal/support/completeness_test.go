// SPDX-License-Identifier: LicenseRef-probectl-TBD

package support

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/version"
)

// TestBundleCompleteness is the EXC-ORG-03 completeness gate: it pins the exact
// set of diagnostics an F500 support contract needs in a support bundle, so
// DROPPING a section reds the build (the bundle silently shrinking is the failure
// mode — an engineer ships a bundle missing the data support needs to triage).
// It also asserts the manifest's file list is EXACTLY the bundle's contents
// (no listed-but-missing, no present-but-unlisted) and that every file is valid,
// non-trivial JSON.
func TestBundleCompleteness(t *testing.T) {
	// The required diagnostic sections. Each answers a real triage question:
	//   version          — what build is this? (the first question on any ticket)
	//   config-redacted  — how is it configured? (secret-stripped allowlist)
	//   health           — what is broken right now? (component health rollup)
	//   self-metrics     — RED/USE on probectl's own pipelines (saturation/errors)
	//   topology-summary — scale shape (tenants/agents/region) without telemetry
	//   runtime          — go version / OS / arch / goroutines / mem / uptime
	//   manifest         — the index (+ the secret-stripped notice)
	required := []string{
		"version.json",
		"config-redacted.json",
		"health.json",
		"self-metrics.json",
		"topology-summary.json",
		"runtime.json",
		"manifest.json",
	}

	src := Sources{
		Version:        version.Info{Version: "v1.2.3", Commit: "deadbee"},
		ConfigRedacted: map[string]any{"database_url": "postgres://u:xxxxx@db/probectl", "envelope_key_configured": true},
		Health:         Health{Status: StatusOK},
		SelfMetrics:    SelfSnapshot(time.Now().Add(-time.Minute)),
		Topology:       TopologySummary{Tenants: 5, Agents: 20, Region: "eu-west"},
		Runtime:        CollectRuntime(time.Now().Add(-time.Hour)),
	}

	var buf bytes.Buffer
	man, err := Generate(&buf, src)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	files, err := ReadBundle(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// 1. Every required section is present.
	for _, want := range required {
		if _, ok := files[want]; !ok {
			t.Errorf("F500 support bundle is INCOMPLETE — missing %s (have %v)", want, keys(files))
		}
	}

	// 2. The manifest enumerates EXACTLY the bundle's files (the index cannot
	// drift from the contents).
	gotFiles := append([]string{}, man.Files...)
	actual := keys(files)
	sort.Strings(gotFiles)
	sort.Strings(actual)
	if len(gotFiles) != len(actual) {
		t.Fatalf("manifest lists %v but bundle contains %v", gotFiles, actual)
	}
	for i := range gotFiles {
		if gotFiles[i] != actual[i] {
			t.Fatalf("manifest/bundle mismatch: manifest=%v bundle=%v", gotFiles, actual)
		}
	}

	// 3. Every file is valid, non-trivial JSON.
	for name, raw := range files {
		if len(raw) < 2 {
			t.Errorf("%s is empty/trivial (%d bytes)", name, len(raw))
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Errorf("%s is not valid JSON: %v", name, err)
		}
	}

	// 4. The manifest carries the secret-stripped notice (the contract that the
	// bundle is safe to attach to a ticket).
	var m map[string]any
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	notes, _ := m["notes"].([]any)
	foundNotice := false
	for _, n := range notes {
		if s, _ := n.(string); len(s) > 0 && contains(s, "SECRET-STRIPPED") {
			foundNotice = true
		}
	}
	if !foundNotice {
		t.Error("manifest must carry the SECRET-STRIPPED notice (the safe-to-attach contract)")
	}
}

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
