// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	if code := run([]string{"-repo-root", repoRoot, "-registry", registry, "-require-complete"}); code != 1 {
		t.Fatalf("run exit = %d, want incomplete-registry failure", code)
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
