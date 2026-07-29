// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"strings"
	"testing"
)

const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

func TestWorkflowImageFindingsAcceptQuotedAndFlowDigestValues(t *testing.T) {
	t.Parallel()

	root, err := loadWorkflow(writeWorkflow(t, `
jobs: {
  quoted: {
    "container": "registry.example/quoted@sha256:`+zeroDigest+`",
    services: {
      database: {"image": "registry.example/database@sha256:`+zeroDigest+`"}
    },
    steps: []
  }
}
`))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := workflowImageFindings(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("digest-pinned quoted/flow images produced findings: %+v", findings)
	}
}

func TestWorkflowImageFindingsCatchAlternateMutableShapes(t *testing.T) {
	t.Parallel()

	root, err := loadWorkflow(writeWorkflow(t, `
jobs:
  quoted:
    services:
      database:
        "image": postgres:16
    steps: []
  flow: {container: {image: "registry.example/flow:v1"}, steps: []}
  matrix:
    strategy:
      matrix:
        include:
          - image: ${{ matrix.image }}
    steps: []
  multiline:
    services:
      database:
        image: >-
          postgres:16
    steps: []
  non-string:
    services:
      database:
        image: {repository: postgres, tag: 16}
    steps: []
`))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := workflowImageFindings(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(findings), 5; got != want {
		t.Fatalf("findings = %d, want %d: %+v", got, want, findings)
	}
	if got, want := findings[2].value, "${{ matrix.image }}"; got != want {
		t.Fatalf("expression value = %q, want exact %q", got, want)
	}
	if got, want := findings[2].reason, "GitHub expression is unresolved"; got != want {
		t.Fatalf("expression reason = %q, want %q", got, want)
	}
}

func TestWorkflowImagesFailClosedOnAliasesAndMergeDataFlow(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"alias": `
image: &image registry.example/pinned@sha256:` + zeroDigest + `
jobs:
  aliased:
    container: *image
    steps: []
`,
		"merge": `
defaults: &defaults {image: "registry.example/hidden:v1"}
jobs:
  merged:
    services:
      database: {<<: *defaults}
    steps: []
`,
	}
	for name, workflow := range tests {
		name, workflow := name, workflow
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := loadWorkflow(writeWorkflow(t, workflow))
			if err == nil {
				t.Fatal("loadWorkflow accepted aliased/merged image data flow")
			}
		})
	}
}

func TestRunImagesFailsOnExpressionEvenWithDigestSuffix(t *testing.T) {
	t.Parallel()

	path := writeWorkflow(t, `
jobs:
  unresolved:
    container: ${{ env.REGISTRY }}/image@sha256:`+zeroDigest+`
    steps: []
`)
	var stdout, stderr strings.Builder
	if code := run([]string{"images", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("run() = %d, want 1; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `${{ env.REGISTRY }}/image@sha256:`+zeroDigest) {
		t.Fatalf("diagnostic did not preserve expression: %q", stdout.String())
	}
}
