// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowInputBudgetsExactAndOnePast(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		base := "jobs: {}\n#"
		exact := base + strings.Repeat("x", maxWorkflowFileBytes-len(base))
		if _, err := loadWorkflow(writeWorkflowRaw(t, exact)); err != nil {
			t.Fatalf("exact byte budget rejected: %v", err)
		}
		if _, err := loadWorkflow(writeWorkflowRaw(t, exact+"x")); err == nil {
			t.Fatal("one-past byte budget was accepted")
		}
	})

	t.Run("depth", func(t *testing.T) {
		workflowAtDepth := func(depth int) string {
			nestedSequences := depth - 2 // root mapping + final scalar
			return "jobs: {}\npadding: " +
				strings.Repeat("[", nestedSequences) + "x" +
				strings.Repeat("]", nestedSequences) + "\n"
		}
		if _, err := loadWorkflow(writeWorkflowRaw(t, workflowAtDepth(maxWorkflowDepth))); err != nil {
			t.Fatalf("exact depth budget rejected: %v", err)
		}
		if _, err := loadWorkflow(writeWorkflowRaw(t, workflowAtDepth(maxWorkflowDepth+1))); err == nil {
			t.Fatal("one-past depth budget was accepted")
		}
	})

	t.Run("nodes", func(t *testing.T) {
		// The root/jobs/job/steps structure contributes seven YAML nodes. Each
		// scalar step contributes one more.
		workflowWithNodes := func(nodes int) string {
			return "jobs:\n  node-budget:\n    steps:\n" +
				strings.Repeat("      - x\n", nodes-7)
		}
		if _, err := loadWorkflow(writeWorkflowRaw(t, workflowWithNodes(maxWorkflowNodes))); err != nil {
			t.Fatalf("exact node budget rejected: %v", err)
		}
		if _, err := loadWorkflow(writeWorkflowRaw(t, workflowWithNodes(maxWorkflowNodes+1))); err == nil {
			t.Fatal("one-past node budget was accepted")
		}
	})

	t.Run("files", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i < maxWorkflowFiles; i++ {
			path := filepath.Join(dir, fmt.Sprintf("%03d.yml", i))
			if err := os.WriteFile(path, []byte("jobs: {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if files, err := workflowFiles([]string{dir}); err != nil {
			t.Fatalf("exact file budget rejected: %v", err)
		} else if len(files) != maxWorkflowFiles {
			t.Fatalf("exact file budget returned %d files, want %d", len(files), maxWorkflowFiles)
		}
		if err := os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("%03d.yml", maxWorkflowFiles)),
			[]byte("jobs: {}\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := workflowFiles([]string{dir}); err == nil {
			t.Fatal("one-past file budget was accepted")
		}
	})
}

func TestPermissionRecordsSeeSemanticYAMLShapes(t *testing.T) {
	t.Parallel()

	path := writeWorkflow(t, `
permissions: {contents: read}
jobs:
  "quoted-read": {permissions: {contents: read}, steps: []}
  "flow-write": {permissions: {pull-requests: write}, steps: []}
  multiline-write:
    permissions: >-
      write-all
    steps: []
`)
	root, err := loadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	records, err := permissionRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool, len(records))
	for _, record := range records {
		got[record.scope+":"+record.job] = record.write
	}
	for key, want := range map[string]bool{
		"workflow:-":          false,
		"job:quoted-read":     false,
		"job:flow-write":      true,
		"job:multiline-write": true,
	} {
		if got[key] != want {
			t.Errorf("%s write = %v, want %v", key, got[key], want)
		}
	}
}

func TestPermissionRecordsFailClosedOnAliasesAndMerges(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"alias": `
read-job: &read-job {permissions: {contents: read}, steps: []}
jobs:
  inherited: *read-job
`,
		"merge": `
jobs:
  inherited:
    <<: {permissions: {contents: write}}
    steps: []
`,
	}
	for name, workflow := range tests {
		name, workflow := name, workflow
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := loadWorkflow(writeWorkflow(t, workflow))
			if err == nil {
				t.Fatal("loadWorkflow accepted an ambiguous YAML data-flow shape")
			}
		})
	}
}

func TestRunPermissionsPreservesQuotedJobIdentity(t *testing.T) {
	t.Parallel()

	path := writeWorkflow(t, `
jobs:
  "quoted-write":
    permissions:
      contents: write
    steps: []
`)
	var stdout, stderr strings.Builder
	if code := run([]string{"permissions", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	if got, want := stdout.String(), "workflow\t-\tread\njob\tquoted-write\twrite\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func writeWorkflow(t *testing.T, contents string) string {
	t.Helper()
	return writeWorkflowRaw(t, strings.TrimSpace(contents)+"\n")
}

func writeWorkflowRaw(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workflow.yml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
