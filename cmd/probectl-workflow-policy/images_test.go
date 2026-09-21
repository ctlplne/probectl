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

func TestWorkflowDockerRunAndPullImagePins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		workflow   string
		wantCode   int
		wantValues []string
	}{
		{
			name: "mutable operands fail",
			workflow: `
jobs:
  planted:
    steps:
      - run: |
          docker run -d --name planted -p 9090:9090 \
            registry.example/x:v1 \
            /bin/true
          docker pull --platform linux/amd64 \
            registry.example/y:v2
`,
			wantCode:   1,
			wantValues: []string{"registry.example/x:v1", "registry.example/y:v2"},
		},
		{
			name: "digest-pinned operands pass",
			workflow: `
jobs:
  planted:
    steps:
      - run: |
          docker run -d --name planted -p 9090:9090 \
            registry.example/x@sha256:` + zeroDigest + ` \
            /bin/true
          docker pull --platform linux/amd64 \
            registry.example/y@sha256:` + zeroDigest + `
`,
			wantCode: 0,
		},
		{
			name: "dynamic subcommand fails closed",
			workflow: `
jobs:
  planted:
    steps:
      - run: |
          CMD=run docker "$CMD" \
            registry.example/x@sha256:` + zeroDigest + `
`,
			wantCode:   1,
			wantValues: []string{"$CMD"},
		},
		{
			name: "dynamic container subcommand fails closed",
			workflow: `
jobs:
  planted:
    steps:
      - run: |
          CMD=run docker container "$CMD" \
            registry.example/x@sha256:` + zeroDigest + `
`,
			wantCode:   1,
			wantValues: []string{"$CMD"},
		},
		{
			name: "dynamic image subcommand fails closed",
			workflow: `
jobs:
  planted:
    steps:
      - run: |
          CMD=pull docker image "$CMD" \
            registry.example/x@sha256:` + zeroDigest + `
`,
			wantCode:   1,
			wantValues: []string{"$CMD"},
		},
		{
			name: "known static non-image subcommands pass",
			workflow: `
jobs:
  planted:
    steps:
      - run: |
          docker logs planted
          docker version
`,
			wantCode: 0,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr strings.Builder
			code := run(
				[]string{"images", writeWorkflow(t, test.workflow)},
				&stdout,
				&stderr,
			)
			if code != test.wantCode {
				t.Fatalf(
					"run() = %d, want %d; stdout = %q; stderr = %q",
					code,
					test.wantCode,
					stdout.String(),
					stderr.String(),
				)
			}
			for _, value := range test.wantValues {
				if !strings.Contains(stdout.String(), value) {
					t.Errorf("diagnostic %q does not contain mutable image %q", stdout.String(), value)
				}
			}
			if test.wantCode == 0 && stdout.Len() != 0 {
				t.Fatalf("digest-pinned workflow produced findings: %q", stdout.String())
			}
		})
	}
}

func TestWorkflowInvokedScriptDockerImagePin(t *testing.T) {
	t.Parallel()

	repository := t.TempDir()
	workflowDirectory := filepath.Join(repository, ".github", "workflows")
	scriptDirectory := filepath.Join(repository, "scripts")
	if err := os.MkdirAll(workflowDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(scriptDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	workflow := filepath.Join(workflowDirectory, "ci.yml")
	if err := os.WriteFile(workflow, []byte(`
jobs:
  helper:
    steps:
      - run: bash scripts/ci-helper.sh
`), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(scriptDirectory, "ci-helper.sh")
	if err := os.WriteFile(
		helper,
		[]byte("#!/usr/bin/env bash\ndocker run --rm postgres:16 true\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr strings.Builder
	if code := run([]string{"images", workflow}, &stdout, &stderr); code != 1 {
		t.Fatalf(
			"mutable workflow helper: run() = %d, want 1; stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
	if !strings.Contains(stdout.String(), "ci-helper.sh") ||
		!strings.Contains(stdout.String(), "postgres:16") {
		t.Fatalf("diagnostic does not identify helper and image: %q", stdout.String())
	}

	if err := os.WriteFile(
		helper,
		[]byte("#!/usr/bin/env bash\nIMAGE=postgres:16\ndocker run --rm \"$IMAGE\" true\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"images", workflow}, &stdout, &stderr); code != 1 {
		t.Fatalf(
			"variable-hidden mutable helper: run() = %d, want 1; stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}

	if err := os.WriteFile(
		helper,
		[]byte("#!/usr/bin/env bash\nimage=postgres:16\ndocker run --rm \"$image\" true\ndocker build -t \"$image\" .\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"images", workflow}, &stdout, &stderr); code != 1 {
		t.Fatalf(
			"run-before-build helper: run() = %d, want 1; stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}

	if err := os.WriteFile(
		helper,
		[]byte("#!/usr/bin/env bash\ndocker run --rm postgres:16@sha256:"+zeroDigest+" true\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"images", workflow}, &stdout, &stderr); code != 0 {
		t.Fatalf(
			"digest-pinned helper: run() = %d, want 0; stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}

	if err := os.WriteFile(
		helper,
		[]byte("#!/usr/bin/env bash\nimage=toolchain:local\ndocker build -t \"$image\" .\ndocker run --rm \"$image\" true\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"images", workflow}, &stdout, &stderr); code != 0 {
		t.Fatalf(
			"locally built helper image: run() = %d, want 0; stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
}
