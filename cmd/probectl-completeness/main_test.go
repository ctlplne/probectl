// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ctlplne/probectl/internal/completeness"
)

func TestInvalidRegistryDoesNotRenderMisleadingLedger(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, "capabilities.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	const valid = "cli: {refs: [\"cli:probectl agent list\", \"cli:probectl test list\"]}"
	const invalid = "cli: {refs: [\"cli:probectl command-that-does-not-exist\"]}"
	mutated := strings.Replace(string(data), valid, invalid, 1)
	if mutated == string(data) {
		t.Fatal("test mutation did not find the expected F1 CLI cell")
	}
	registry := filepath.Join(t.TempDir(), "capabilities.yaml")
	if err := os.WriteFile(registry, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	jsonPath := filepath.Join(outDir, "ledger.json")
	htmlPath := filepath.Join(outDir, "ledger.html")
	if code := run([]string{
		"-repo-root", repoRoot,
		"-registry", registry,
		"-ledger-json", jsonPath,
		"-ledger-html", htmlPath,
	}); code != 1 {
		t.Fatalf("run exit = %d, want validation failure", code)
	}
	for _, path := range []string{jsonPath, htmlPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("invalid registry rendered %s; stat error = %v", path, err)
		}
	}
}

func TestRequireCompleteRejectsAcknowledgedGaps(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := completeness.LoadRegistry(filepath.Join(repoRoot, "capabilities.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Capabilities) == 0 {
		t.Fatal("registry has no capability to mutate")
	}
	parsed.Capabilities[0].EvidenceStatus = "partial"
	parsed.Capabilities[0].UI = completeness.Cell{Gap: "No user-interface receipt exists for this deliberately mutated fixture row."}
	mutated, err := yaml.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(t.TempDir(), "capabilities.yaml")
	if err := os.WriteFile(registry, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	refusal := captureStderr(t, func() {
		code = run([]string{"-repo-root", repoRoot, "-registry", registry, "-require-complete"})
	})
	if code != 1 {
		t.Fatalf("run exit = %d, want incomplete-registry failure; stderr:\n%s", code, refusal)
	}

	// DPR-251: a release blocked by this gate produces exactly one artifact —
	// this message. A bare count is not an actionable one, so the refusal must
	// name the blocking row, its owner, and the reason the registry recorded.
	blocked := parsed.Capabilities[0]
	for _, want := range []string{
		"completeness-gate: incomplete",
		blocked.ID + ".ui",
		blocked.Owner,
		"No user-interface receipt exists for this deliberately mutated fixture row.",
		"blocking cells by dimension:",
		"ui=",
	} {
		if !strings.Contains(refusal, want) {
			t.Errorf("strict-gate refusal does not mention %q; stderr:\n%s", want, refusal)
		}
	}
}

// captureStderr redirects the process stderr the gate writes to through a file
// rather than a pipe: the refusal lists every blocking row, which is larger
// than a pipe buffer, and a blocked reader would deadlock the gate under test.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stderr.txt")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = file
	defer func() {
		os.Stderr = saved
		file.Close()
	}()
	fn()
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The count in the message and the rows under it come from two code paths, so a
// drift between them would send an operator hunting for work that is not there.
func TestStrictGateGapCountMatchesTheRowsItNames(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := completeness.LoadRegistry(filepath.Join(repoRoot, "capabilities.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ledger := completeness.NewLedger("capabilities.yaml", registry)
	if got := len(ledger.Gaps()); got != ledger.Summary.GapCells {
		t.Fatalf("the shipped registry reports %d acknowledged gap(s) but names %d row(s)", ledger.Summary.GapCells, got)
	}
}

func TestSelftestCannotBypassStrictEvaluationOrRenderLedgers(t *testing.T) {
	tests := [][]string{
		{"-selftest", "-require-complete"},
		{"-selftest", "-ledger-json", filepath.Join(t.TempDir(), "ledger.json")},
		{"-selftest", "-ledger-html", filepath.Join(t.TempDir(), "ledger.html")},
	}
	for _, args := range tests {
		if code := run(args); code != 2 {
			t.Fatalf("run(%v) exit = %d, want usage failure", args, code)
		}
	}
}
