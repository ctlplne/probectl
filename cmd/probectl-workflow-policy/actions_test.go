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
)

const (
	zeroActionSHA = "0000000000000000000000000000000000000000"
)

func TestRunActionsAcceptsEveryImmutableSemanticShape(t *testing.T) {
	path := writeWorkflow(t, `
jobs:
  block:
    steps:
      - "uses": "actions/checkout@`+zeroActionSHA+`"
      - {uses: "actions/setup-go@`+zeroActionSHA+`"}
      - uses: ./.github/actions/lint
      - uses: docker://alpine@sha256:`+zeroDigest+`
  reusable-local:
    uses: ./.github/workflows/reusable.yml
  reusable-remote:
    uses: example/repository/.github/workflows/reusable.yml@`+zeroActionSHA+`
`)
	var stdout, stderr strings.Builder
	if code := run([]string{"actions", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(actions) = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestRunActionsRejectsMutableAndAmbiguousSemanticShapes(t *testing.T) {
	tests := map[string]string{
		"quoted mutable": `
jobs:
  test:
    steps:
      - "uses": actions/checkout@v6
`,
		"flow mutable": `
jobs: {test: {steps: [{uses: actions/setup-go@v6}]}}
`,
		"expression": `
jobs:
  test:
    steps:
      - uses: ${{ matrix.action }}
`,
		"docker tag": `
jobs:
  test:
    steps:
      - uses: docker://alpine:3.22
`,
		"docker short digest": `
jobs:
  test:
    steps:
      - uses: docker://alpine@sha256:abcd
`,
		"non-string": `
jobs:
  test:
    steps:
      - uses: {repository: actions/checkout, ref: v6}
`,
		"alias": `
action: &action actions/checkout@` + zeroActionSHA + `
jobs:
  test:
    steps:
      - uses: *action
`,
		"merge": `
action: &action {uses: actions/checkout@v6}
jobs:
  test:
    steps:
      - {<<: *action}
`,
	}
	for name, workflow := range tests {
		name, workflow := name, workflow
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if code := run([]string{"actions", writeWorkflow(t, workflow)}, &stdout, &stderr); code != 1 {
				t.Fatalf("run(actions) = %d, want 1; stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunPermissionsReportsActionExecution(t *testing.T) {
	path := writeWorkflow(t, `
jobs:
  coverage-comment:
    permissions: {pull-requests: write}
    steps: [{"uses": "actions/github-script@v7"}]
`)
	var stdout, stderr strings.Builder
	if code := run([]string{"permissions", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(permissions) = %d, stderr = %q", code, stderr.String())
	}
	if got, want := stdout.String(), "workflow\t-\tread\tnone\njob\tcoverage-comment\twrite\taction\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestActionPinGateUsesSemanticPolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check_action_pins.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	if !strings.Contains(script, "probectl-workflow-policy actions") {
		t.Fatal("action pin gate does not call the semantic workflow-policy actions command")
	}
	if strings.Contains(script, `grep -rnE '^[[:space:]-]*uses:'`) {
		t.Fatal("action pin gate still enumerates action keys lexically")
	}
}
