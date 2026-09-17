// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"encoding/json"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeRegistryIsStrictAndDeterministic(t *testing.T) {
	const valid = `schema: probectl.capabilities/v1
source_catalog: docs/claims/release-catalog.json
capabilities:
  - id: F2
    name: second
    status: delivered
    owner: owner
  - id: F1
    name: first
    status: delivered
    owner: owner
`
	registry, err := DecodeRegistry([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{registry.Capabilities[0].ID, registry.Capabilities[1].ID}; !reflect.DeepEqual(got, []string{"F1", "F2"}) {
		t.Fatalf("sorted IDs = %v", got)
	}
	if _, err := DecodeRegistry([]byte(valid + "unknown_field: true\n")); err == nil || !strings.Contains(err.Error(), "field unknown_field") {
		t.Fatalf("unknown field error = %v", err)
	}
	if _, err := DecodeRegistry([]byte(valid + "---\nschema: second\n")); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("trailing document error = %v", err)
	}
	if _, err := DecodeRegistry([]byte(valid + "---\n[unterminated\n")); err == nil || !strings.Contains(err.Error(), "trailing content") {
		t.Fatalf("malformed trailing document error = %v", err)
	}
}

func TestValidatorChecksEveryEvidenceSurface(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	if violations := validator.Validate(registry); len(violations) != 0 {
		t.Fatalf("baseline violations = %#v", violations)
	}

	tests := []struct {
		name string
		edit func(*Registry)
		code string
		cell string
	}{
		{name: "missing cell", edit: func(r *Registry) { r.Capabilities[0].CLI = Cell{} }, code: "missing-cell", cell: "cli"},
		{name: "ambiguous cell", edit: func(r *Registry) {
			r.Capabilities[0].CLI.NoneByDesign = "A sufficiently long but conflicting reason for absence."
		}, code: "ambiguous-cell", cell: "cli"},
		{name: "weak reason", edit: func(r *Registry) { r.Capabilities[0].CLI = Cell{NoneByDesign: "too short"} }, code: "weak-none-by-design", cell: "cli"},
		{name: "gap on complete evidence", edit: func(r *Registry) {
			r.Capabilities[0].CLI = Cell{Gap: "The executable CLI proof is not implemented for this capability yet."}
		}, code: "gap-status", cell: "cli"},
		{name: "weak gap", edit: func(r *Registry) {
			r.Capabilities[0].EvidenceStatus = "partial"
			r.Capabilities[0].CLI = Cell{Gap: "too short"}
		}, code: "weak-gap", cell: "cli"},
		{name: "unknown api", edit: func(r *Registry) { r.Capabilities[0].API = Cell{Refs: []string{"api:GET /v1/missing"}} }, code: "invalid-ref", cell: "api"},
		{name: "unknown cli", edit: func(r *Registry) { r.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl missing command"}} }, code: "invalid-ref", cell: "cli"},
		{name: "unknown ui", edit: func(r *Registry) { r.Capabilities[0].UI = Cell{Refs: []string{"ui:F1@/missing"}} }, code: "invalid-ref", cell: "ui"},
		{name: "borrow unrelated ui", edit: func(r *Registry) { r.Capabilities[0].UI = Cell{Refs: []string{"ui:F2@/bar"}} }, code: "invalid-ref", cell: "ui"},
		{name: "unused ui alias", edit: func(r *Registry) {
			r.Capabilities[0].UIAliases = map[string]string{"F2": "The fixture declares a deliberate but currently unused surface alias."}
		}, code: "ui-alias-unused", cell: "ui"},
		{name: "undocumented config", edit: func(r *Registry) { r.Capabilities[0].ConfigKeys = Cell{Refs: []string{"config:PROBECTL_MISSING"}} }, code: "invalid-ref", cell: "config_keys"},
		{name: "config substring", edit: func(r *Registry) { r.Capabilities[0].ConfigKeys = Cell{Refs: []string{"config:PROBECTL_FO"}} }, code: "invalid-ref", cell: "config_keys"},
		{name: "config prose substring", edit: func(r *Registry) { r.Capabilities[0].ConfigKeys = Cell{Refs: []string{"config:the"}} }, code: "invalid-ref", cell: "config_keys"},
		{name: "path escape", edit: func(r *Registry) { r.Capabilities[0].Engine = Cell{Refs: []string{"file:../outside"}} }, code: "invalid-ref", cell: "engine"},
		{name: "wrong engine tree", edit: func(r *Registry) { r.Capabilities[0].Engine = Cell{Refs: []string{"file:docs/foo.md"}} }, code: "invalid-ref", cell: "engine"},
		{name: "umbrella engine tree", edit: func(r *Registry) { r.Capabilities[0].Engine = Cell{Refs: []string{"file:internal"}} }, code: "invalid-ref", cell: "engine"},
		{name: "wrong binary tree", edit: func(r *Registry) {
			r.Capabilities[0].Binary = Cell{Refs: []string{"file:internal/foo/engine.go#package foo"}}
		}, code: "invalid-ref", cell: "binary"},
		{name: "generic control binary seam", edit: func(r *Registry) {
			r.Capabilities[0].Binary = Cell{Refs: []string{"file:cmd/probectl-control/serve_runtime.go#func runServe"}}
		}, code: "invalid-ref", cell: "binary"},
		{name: "generic control constructor seam", edit: func(r *Registry) {
			r.Capabilities[0].Binary = Cell{Refs: []string{"file:cmd/probectl-control/serve_runtime.go#control.New(rt.cfg"}}
		}, code: "invalid-ref", cell: "binary"},
		{name: "wrong docs tree", edit: func(r *Registry) {
			r.Capabilities[0].Docs = Cell{Refs: []string{"file:internal/foo/engine.go#package foo"}}
		}, code: "invalid-ref", cell: "docs"},
		{name: "wrong telemetry tree", edit: func(r *Registry) { r.Capabilities[0].Telemetry = Cell{Refs: []string{"file:README.md"}} }, code: "invalid-ref", cell: "telemetry"},
		{name: "umbrella telemetry tree", edit: func(r *Registry) { r.Capabilities[0].Telemetry = Cell{Refs: []string{"file:internal"}} }, code: "invalid-ref", cell: "telemetry"},
		{name: "documentation directory", edit: func(r *Registry) { r.Capabilities[0].Docs = Cell{Refs: []string{"file:docs#Fixture capability"}} }, code: "invalid-ref", cell: "docs"},
		{name: "wrong migration tree", edit: func(r *Registry) { r.Capabilities[0].Migration = Cell{Refs: []string{"file:internal/foo/engine.go"}} }, code: "invalid-ref", cell: "migration"},
		{name: "generic test anchor", edit: func(r *Registry) {
			r.Capabilities[0].RealStackProof = Cell{Refs: []string{"test:test/integration/foo_integration_test.go#Test"}}
		}, code: "invalid-ref", cell: "real_stack_proof"},
		{name: "proof needs anchor", edit: func(r *Registry) {
			r.Capabilities[0].RealStackProof = Cell{Refs: []string{"test:test/integration/foo_integration_test.go"}}
		}, code: "invalid-ref", cell: "real_stack_proof"},
		{name: "uncataloged unit proof", edit: func(r *Registry) {
			r.Capabilities[0].RealStackProof = Cell{Refs: []string{"test:internal/foo/foo_test.go#TestUnrelatedUnit"}}
		}, code: "invalid-ref", cell: "real_stack_proof"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneRegistry(t, registry)
			tc.edit(&candidate)
			violations := validator.Validate(candidate)
			if !containsViolation(violations, "F1", tc.cell, tc.code) {
				t.Fatalf("violations = %#v; want %s/%s", violations, tc.cell, tc.code)
			}
		})
	}
}

func TestValidatorRejectsSymlinkEscape(t *testing.T) {
	root := fixtureRepo(t)
	outside := filepath.Join(t.TempDir(), "outside.go")
	if err := os.WriteFile(outside, []byte("package outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "internal", "foo", "escape.go")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Engine = Cell{Refs: []string{"file:internal/foo/escape.go"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "engine", "invalid-ref") {
		t.Fatalf("violations = %#v; want symlink escape rejection", violations)
	}
}

func TestValidatorRejectsInRepositoryEvidenceRelabelingSymlink(t *testing.T) {
	root := fixtureRepo(t)
	target := filepath.Join(root, "internal", "foo", "hidden.txt")
	if err := os.WriteFile(target, []byte("<!-- Fixture capability -->\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "docs", "fake.md")
	if err := os.Symlink(filepath.Join("..", "internal", "foo", "hidden.txt"), link); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Docs = Cell{Refs: []string{"file:docs/fake.md#Fixture capability"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "docs", "invalid-ref") {
		t.Fatalf("violations = %#v; want in-repository evidence relabeling symlink rejected", violations)
	}
}

func TestValidatorRejectsSymlinkInsideAnchoredDirectory(t *testing.T) {
	root := fixtureRepo(t)
	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("secret anchor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "docs", "proof")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape.md")); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Docs = Cell{Refs: []string{"file:docs/proof#secret anchor"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "docs", "invalid-ref") {
		t.Fatalf("violations = %#v; want nested symlink rejection", violations)
	}
}

func TestValidatorRequiresCanonicalReleaseCatalog(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.SourceCatalog = "docs/claims/alternate.json"
	if violations := validator.Validate(registry); !containsViolation(violations, "", "", "catalog") {
		t.Fatalf("violations = %#v; want canonical catalog rejection", violations)
	}
}

func TestValidatorTracksActualSpecialCLIDispatchCases(t *testing.T) {
	root := fixtureRepo(t)
	commands := filepath.Join(root, "internal", "cli", "commands.go")
	data, err := os.ReadFile(commands)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(data), `case "list":`, `case "deleted-list":`, 1)
	if mutated == string(data) {
		t.Fatal("CLI dispatch mutation did not apply")
	}
	if err := os.WriteFile(commands, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := validator.Validate(fixtureRegistry())
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want actual CLI branch deletion rejection", violations)
	}
}

func TestValidatorRejectsCommentMasqueradingAsGoTest(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "test", "integration", "foo_integration_test.go")
	if err := os.WriteFile(path, []byte("package integration\n// func TestFooRealStack(\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	violations := validator.Validate(fixtureRegistry())
	if !containsViolation(violations, "F1", "real_stack_proof", "invalid-ref") {
		t.Fatalf("violations = %#v; want comment-only test rejection", violations)
	}
}

func TestRealStackProofCatalogAndRunnerAreStrict(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		old      string
		new      string
		wantText string
	}{
		{
			name: "unknown catalog field", path: "test/real-stack-proofs.json",
			old: `"schema":"probectl.real-stack-proofs/v1"`, new: `"schema":"probectl.real-stack-proofs/v1","unknown":true`,
			wantText: "unknown field",
		},
		{
			name: "unit file masquerades as integration", path: "test/integration/foo_integration_test.go",
			old: "//go:build integration\n\n", new: "",
			wantText: "positive integration build constraint",
		},
		{
			name: "negated integration constraint", path: "test/integration/foo_integration_test.go",
			old: "//go:build integration", new: "//go:build !integration",
			wantText: "positive integration build constraint",
		},
		{
			name: "CI runner removed", path: ".github/workflows/ci.yml",
			old: "run: make test-integration", new: "run: make unit-tests-only",
			wantText: "missing executable command \"make test-integration\"",
		},
		{
			name: "commented CI runner", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", new: "      # - run: make test-integration",
			wantText: "missing executable command \"make test-integration\"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(data), tc.old, tc.new, 1)
			if mutated == string(data) {
				t.Fatalf("mutation did not find %q", tc.old)
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("NewValidator error = %v, want %q", err, tc.wantText)
			}
		})
	}
}

func TestGoTestEnvGuardRequiresExecutableAST(t *testing.T) {
	commentOnly := []byte(`package proof
import "testing"
func TestE2E(t *testing.T) {
	// if os.Getenv("PROBECTL_E2E") != "1" { t.Skip("guard") }
}
`)
	if goTestHasEnvGuard(commentOnly, "TestE2E", "PROBECTL_E2E", "Getenv", token.NEQ, "1", "Skip") {
		t.Fatal("comment-only E2E guard was accepted")
	}
	stringOnly := []byte(`package proof
import "testing"
func TestE2E(t *testing.T) {
	_ = "if os.Getenv(\"PROBECTL_E2E\") != \"1\" { t.Skip() }"
}
`)
	if goTestHasEnvGuard(stringOnly, "TestE2E", "PROBECTL_E2E", "Getenv", token.NEQ, "1", "Skip") {
		t.Fatal("string-only E2E guard was accepted")
	}
	deadGuard := []byte(`package proof
import "testing"
func TestE2E(t *testing.T) {
	if false { if os.Getenv("PROBECTL_E2E") != "1" { t.Skip("guard") } }
}
`)
	if goTestHasEnvGuard(deadGuard, "TestE2E", "PROBECTL_E2E", "Getenv", token.NEQ, "1", "Skip") {
		t.Fatal("constant-false E2E guard was accepted")
	}
	wrongPackage := []byte(`package proof
import "testing"
func TestE2E(t *testing.T) {
	if decoy.Getenv("PROBECTL_E2E") != "1" { t.Skip("guard") }
}
`)
	if goTestHasEnvGuard(wrongPackage, "TestE2E", "PROBECTL_E2E", "Getenv", token.NEQ, "1", "Skip") {
		t.Fatal("non-os Getenv guard was accepted")
	}
}

func TestRealStackCatalogRejectsNoopTestBodies(t *testing.T) {
	tests := []struct {
		name        string
		replacement string
	}{
		{name: "empty body", replacement: `func TestFooRealStack(t *testing.T) {}`},
		{name: "leading bare return", replacement: `func TestFooRealStack(t *testing.T) { return }`},
		{name: "unconditional skip", replacement: `func TestFooRealStack(t *testing.T) { t.Skip("disabled") }`},
		{name: "unconditional skip now", replacement: `func TestFooRealStack(t *testing.T) { t.SkipNow() }`},
		{name: "constant true skip", replacement: `func TestFooRealStack(t *testing.T) { if true { t.SkipNow() } }`},
		{name: "constant expression skip", replacement: `func TestFooRealStack(t *testing.T) { if true == true { t.SkipNow() } }`},
		{name: "deferred skip", replacement: `func TestFooRealStack(t *testing.T) { defer t.SkipNow() }`},
		{name: "method expression skip", replacement: `func TestFooRealStack(t *testing.T) { (*testing.T).SkipNow(t) }`},
		{name: "skip method alias", replacement: `func TestFooRealStack(t *testing.T) { skip := t.SkipNow; skip() }`},
		{name: "composite literal only", replacement: `func TestFooRealStack(t *testing.T) { _ = struct{}{} }`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "test", "integration", "foo_integration_test.go")
			writeFixtureMutation(t, path, `func TestFooRealStack(t *testing.T) { t.Setenv("PROBECTL_FIXTURE_PROOF", "executed") }`, tc.replacement)
			if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), "no-op") {
				t.Fatalf("NewValidator error = %v, want no-op test rejection", err)
			}
		})
	}
}

func TestRealStackCatalogAllowsProofWorkBeforeBareReturn(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "test", "integration", "foo_integration_test.go")
	writeFixtureMutation(t, path,
		`func TestFooRealStack(t *testing.T) { t.Setenv("PROBECTL_FIXTURE_PROOF", "executed") }`,
		`func TestFooRealStack(t *testing.T) { t.Setenv("PROBECTL_FIXTURE_PROOF", "executed"); return }`)
	if _, err := NewValidator(root); err != nil {
		t.Fatalf("NewValidator rejected executed proof followed by return: %v", err)
	}
}

func TestDeviceLiveRetryMustFailAfterExhaustion(t *testing.T) {
	script := `set -e
for attempt in 1 2; do
  if go test ./internal/device; then
    exit 0
  fi
done
exit 1
`
	if !shellInvokesInControlFlow(script, []string{"go", "test"}) || !shellEndsWithFailure(script) {
		t.Fatal("fail-closed retry script was rejected")
	}
	if shellEndsWithFailure(strings.Replace(script, "exit 1", "exit 0", 1)) {
		t.Fatal("retry script with green exhaustion was accepted")
	}
}

func TestRealStackRunnerRejectsDecoyStructure(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		old         string
		replacement string
		want        string
	}{
		{
			name: "command moved to unrelated make target", path: "Makefile",
			old: "test-integration:\n", replacement: "unrelated-integration:\n",
			want: `missing target "test-integration"`,
		},
		{
			name: "command moved to unrelated workflow job", path: ".github/workflows/ci.yml",
			old: "  integration:\n", replacement: "  unrelated:\n",
			want: `missing job "integration"`,
		},
		{
			name: "workflow step is disabled", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - if: \"false\"\n        run: make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow job is disabled", path: ".github/workflows/ci.yml",
			old: "  integration:\n", replacement: "  integration:\n    if: false\n",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow step may ignore failure", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - continue-on-error: true\n        run: make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow job may ignore failure", path: ".github/workflows/ci.yml",
			old: "  integration:\n", replacement: "  integration:\n    continue-on-error: true\n",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow job overrides go", path: ".github/workflows/ci.yml",
			old: "  integration:\n", replacement: "  integration:\n    env:\n      GO: true\n",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow step has dynamic condition", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - if: ${{ github.ref == 'refs/heads/main' }}\n        run: make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow exits before command", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          exit 0\n          make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow exits after a same line prelude", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          true; exit 0\n          make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow exits through logical list", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          true && exit 0\n          make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow masks command failure", path: ".github/workflows/ci.yml",
			old: "run: make test-integration", replacement: "run: make test-integration || true",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow backgrounds command", path: ".github/workflows/ci.yml",
			old: "run: make test-integration", replacement: "run: make test-integration &",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow conditionally runs command", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          if test -n \"${RUN_PROOF:-}\"; then\n            make test-integration\n          fi",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow shadows make command", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          make() { return 0; }\n          make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow shadows make with function keyword", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          function make(){ return 0; }\n          make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow shadows make with spaced function", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          make () { return 0; }\n          make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow custom shell masks failure", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - shell: bash -c '{0}; true'\n        run: make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow default shell masks failure", path: ".github/workflows/ci.yml",
			old: "jobs:\n", replacement: "defaults:\n  run:\n    shell: bash -c '{0}; true'\njobs:\n",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow job default shell masks failure", path: ".github/workflows/ci.yml",
			old: "  integration:\n", replacement: "  integration:\n    defaults:\n      run:\n        shell: bash -c '{0}; true'\n",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow disables errexit before command", path: ".github/workflows/ci.yml",
			old: "      - run: make test-integration", replacement: "      - run: |\n          set -e\n          set +e\n          make test-integration\n          true",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "workflow only echoes command", path: ".github/workflows/ci.yml",
			old: "run: make test-integration", replacement: "run: echo make test-integration",
			want: `missing executable command "make test-integration"`,
		},
		{
			name: "root module removed from loop", path: "Makefile",
			old: "GO_MODULE_DIRS := . test", replacement: "GO_MODULE_DIRS := test",
			want: "does not include the root module",
		},
		{
			name: "root module overridden after valid assignment", path: "Makefile",
			old: "GO_MODULE_DIRS := . test", replacement: "GO_MODULE_DIRS := . test\nGO_MODULE_DIRS := test",
			want: "does not include the root module",
		},
		{
			name: "configured go command replaced", path: "Makefile",
			old: "GO ?= go", replacement: "GO ?= true",
			want: "does not bind $(GO) to the Go tool",
		},
		{
			name: "integration runner narrows packages", path: "Makefile",
			old: "./...", replacement: "./internal/crypto",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner disables all tests", path: "Makefile",
			old: "-tags=integration", replacement: "-tags=integration -run '^$'",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner uses test binary selector", path: "Makefile",
			old: "-tags=integration", replacement: "-tags=integration -test.run='^$'",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner sets zero count", path: "Makefile",
			old: "-tags=integration", replacement: "-tags=integration -count 0",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner sets padded zero count", path: "Makefile",
			old: "-tags=integration", replacement: "-tags=integration -count=00",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner injects goflags", path: "Makefile",
			old: "cd $$d && $(GO) test", replacement: "cd $$d && GOFLAGS=-run=^$ $(GO) test",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner only echoes go test", path: "Makefile",
			old: "$(GO) test -tags=integration", replacement: "echo $(GO) test -tags=integration",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner pipes go test to true", path: "Makefile",
			old: "$(GO) test -tags=integration ./...", replacement: "$(GO) test -tags=integration ./... | true",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner masks go test failure", path: "Makefile",
			old: ") || exit 1;", replacement: ") || true;",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner masks failure with later command", path: "Makefile",
			old: "./... )", replacement: "./...; true )",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration runner exits before root command", path: "Makefile",
			old: "for d in $(GO_MODULE_DIRS); do", replacement: "exit 0; for d in $(GO_MODULE_DIRS); do",
			want: "does not execute go test with the integration tag and ./...",
		},
		{
			name: "integration wrapper exits without forwarding", path: "scripts/with_integration_stack_lock.sh",
			old: `"$@"`, replacement: "exit 0",
			want: "does not fail-closed while forwarding its command",
		},
		{
			name: "integration wrapper rebinds command arguments", path: "scripts/with_integration_stack_lock.sh",
			old: "shift\n", replacement: "shift\nset -- true\n",
			want: "does not fail-closed while forwarding its command",
		},
		{
			name: "integration target is redefined", path: "Makefile",
			old: "done'\n", replacement: "done'\n\ntest-integration:\n\t@true\n",
			want: `repeats target "test-integration"`,
		},
		{
			name: "integration target is redefined with whitespace", path: "Makefile",
			old: "done'\n", replacement: "done'\n\ntest-integration :\n\t@true\n",
			want: `repeats target "test-integration"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			writeFixtureMutation(t, path, tc.old, tc.replacement)
			if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewValidator error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRealStackRunnerAllowsFailurePreservingRedirection(t *testing.T) {
	root := fixtureRepo(t)
	writeFixtureMutation(t, filepath.Join(root, ".github", "workflows", "ci.yml"),
		"run: make test-integration", "run: make test-integration 2>&1")
	writeFixtureMutation(t, filepath.Join(root, "Makefile"),
		"./... )", "./... 2>&1 )")
	if _, err := NewValidator(root); err != nil {
		t.Fatalf("NewValidator rejected failure-preserving stderr redirection: %v", err)
	}
}

func TestValidatorRejectsCrossCapabilityProofBinding(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "test", "real-stack-proofs.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(data), `"capabilities":["F1"]`, `"capabilities":["F2"]`, 1)
	if mutated == string(data) {
		t.Fatal("proof binding mutation did not apply")
	}
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := validator.Validate(fixtureRegistry())
	if !containsViolation(violations, "F1", "real_stack_proof", "invalid-ref") {
		t.Fatalf("violations = %#v; want F1 proof binding rejection", violations)
	}
	if !containsViolation(violations, "F2", "real_stack_proof", "proof-catalog-capability") {
		t.Fatalf("violations = %#v; want out-of-denominator binding rejection", violations)
	}
}

func TestValidatorRejectsStaleProofCatalogBinding(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].EvidenceStatus = "partial"
	registry.Capabilities[0].RealStackProof = Cell{Gap: "The previously cataloged proof was rejected by an independent semantic audit."}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "real_stack_proof", "proof-catalog-stale") {
		t.Fatalf("violations = %#v; want stale proof binding rejection", violations)
	}
}

func TestValidatorEnforcesExactReleaseCatalogDenominator(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Owner = "wrong"
	registry.Capabilities = append(registry.Capabilities, registry.Capabilities[0])
	registry.Capabilities[1].ID = "EXTRA"
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "", "catalog-owner") {
		t.Fatalf("missing catalog-owner violation: %#v", violations)
	}
	if !containsViolation(violations, "EXTRA", "", "catalog-extra") {
		t.Fatalf("missing catalog-extra violation: %#v", violations)
	}
	registry.Capabilities = nil
	if violations := validator.Validate(registry); !containsViolation(violations, "F1", "", "catalog-missing") {
		t.Fatalf("missing catalog-missing violation: %#v", violations)
	}
}

func TestValidatorRejectsReleaseCatalogKindReclassification(t *testing.T) {
	root := fixtureRepo(t)
	catalog := filepath.Join(root, "docs", "claims", "release-catalog.json")
	writeFixtureMutation(t, catalog, `"kind":"capability"`, `"kind":"legacy-property"`)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := validator.Validate(fixtureRegistry())
	if !containsViolation(violations, "F1", "", "catalog-kind") {
		t.Fatalf("violations = %#v; want independent denominator to reject kind reclassification", violations)
	}
}

func TestValidatorRequiresStrictReleaseCatalogSchema(t *testing.T) {
	tests := []struct {
		name     string
		oldValue string
		newValue string
	}{
		{name: "wrong schema", oldValue: `"schema":"probectl.release-claim-catalog/v1"`, newValue: `"schema":"wrong"`},
		{name: "unknown field", oldValue: `"claims":`, newValue: `"unexpected":true,"claims":`},
		{name: "duplicate key", oldValue: `"claims":`, newValue: `"claims":[],"claims":`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			catalog := filepath.Join(root, "docs", "claims", "release-catalog.json")
			writeFixtureMutation(t, catalog, tc.oldValue, tc.newValue)
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			violations := validator.Validate(fixtureRegistry())
			if !containsViolation(violations, "", "", "catalog") {
				t.Fatalf("violations = %#v; want malformed release catalog rejected", violations)
			}
		})
	}
}

func TestCompletenessPoliciesRejectDuplicateJSONKeys(t *testing.T) {
	root := fixtureRepo(t)
	policy := filepath.Join(root, "docs", "claims", "completeness-none-by-design.json")
	if err := os.WriteFile(policy, []byte(`{"schema":"probectl.completeness-none-by-design/v1","cells":[],"cells":["F1.migration"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("NewValidator error = %v; want duplicate JSON object key rejected", err)
	}
}

func TestValidatorRequiresExactNoneByDesignPolicy(t *testing.T) {
	t.Run("unapproved registry exclusion", func(t *testing.T) {
		root := fixtureRepo(t)
		validator, err := NewValidator(root)
		if err != nil {
			t.Fatal(err)
		}
		registry := fixtureRegistry()
		registry.Capabilities[0].CLI = Cell{NoneByDesign: "This planted CLI exclusion has a long rationale but no policy approval."}
		violations := validator.Validate(registry)
		if !containsViolation(violations, "F1", "cli", "unapproved-none-by-design") {
			t.Fatalf("violations = %#v; want unapproved exclusion rejected", violations)
		}
	})

	t.Run("unused policy preapproval", func(t *testing.T) {
		root := fixtureRepo(t)
		policy := filepath.Join(root, "docs", "claims", "completeness-none-by-design.json")
		writeFixtureMutation(t, policy, `"F1.migration"]`, `"F1.migration","F1.cli"]`)
		validator, err := NewValidator(root)
		if err != nil {
			t.Fatal(err)
		}
		violations := validator.Validate(fixtureRegistry())
		if !containsViolation(violations, "F1", "cli", "stale-none-by-design-policy") {
			t.Fatalf("violations = %#v; want unused policy preapproval rejected", violations)
		}
	})
}

func TestReasonedNoneByDesignCellPasses(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Migration = Cell{NoneByDesign: "The capability owns no schema and therefore needs no migration."}
	if violations := validator.Validate(registry); len(violations) != 0 {
		t.Fatalf("violations = %#v", violations)
	}
}

func TestAcknowledgedGapRequiresPartialEvidenceStatus(t *testing.T) {
	root := fixtureRepo(t)
	if err := os.WriteFile(filepath.Join(root, "test", "real-stack-proofs.json"), []byte(`{"schema":"probectl.real-stack-proofs/v1","proofs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].EvidenceStatus = "partial"
	registry.Capabilities[0].RealStackProof = Cell{Gap: "No real-service execution receipt exists for this fixture capability yet."}
	if violations := validator.Validate(registry); len(violations) != 0 {
		t.Fatalf("violations = %#v", violations)
	}

	registry.Capabilities[0].RealStackProof = Cell{Refs: []string{"test:test/integration/foo_integration_test.go#TestFooRealStack"}}
	if violations := validator.Validate(registry); !containsViolation(violations, "F1", "", "evidence-status") {
		t.Fatalf("violations = %#v; want partial-without-gap rejection", violations)
	}
}

func TestCapabilitySpecificInternalControlBinarySeamPasses(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Binary = Cell{Refs: []string{"file:internal/control/server.go#s.foo = buildFoo"}}
	if violations := validator.Validate(registry); len(violations) != 0 {
		t.Fatalf("violations = %#v", violations)
	}
}

func TestReasonedUIAliasPasses(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].UI = Cell{Refs: []string{"ui:F2@/bar"}}
	registry.Capabilities[0].UIAliases = map[string]string{
		"F2": "This fixture intentionally reuses the related F2 operator surface.",
	}
	if violations := validator.Validate(registry); len(violations) != 0 {
		t.Fatalf("violations = %#v", violations)
	}
}

func TestLedgerArtifactsAreDeterministic(t *testing.T) {
	registry := fixtureRegistry()
	ledger := NewLedger("capabilities.yaml", registry)
	if ledger.Summary.Capabilities != 1 || ledger.Summary.FullyDispositioned != 1 || ledger.Summary.DeliveredCapabilities != 1 || ledger.Summary.EvidenceCompleteCapabilities != 1 || ledger.Summary.TotalCells != len(CellNames) {
		t.Fatalf("summary = %#v", ledger.Summary)
	}
	dir := t.TempDir()
	jsonA, jsonB := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	htmlA, htmlB := filepath.Join(dir, "a.html"), filepath.Join(dir, "b.html")
	if err := WriteJSON(jsonA, ledger); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(jsonB, ledger); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(htmlA, ledger); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(htmlB, ledger); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{jsonA, jsonB}, {htmlA, htmlB}} {
		a, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("artifacts differ: %v", pair)
		}
	}
	html, err := os.ReadFile(htmlA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "F1") || !strings.Contains(string(html), "real stack proof") {
		t.Fatalf("HTML ledger omits required columns/row")
	}
}

func TestLedgerDoesNotCountAcknowledgedGapAsCoverage(t *testing.T) {
	registry := fixtureRegistry()
	registry.Capabilities[0].EvidenceStatus = "partial"
	registry.Capabilities[0].RealStackProof = Cell{Gap: "No real-service execution receipt exists for this fixture capability yet."}
	ledger := NewLedger("capabilities.yaml", registry)
	if ledger.Summary.GapCells != 1 || ledger.Summary.FullyDispositioned != 0 || ledger.Summary.EvidencePartialCapabilities != 1 {
		t.Fatalf("summary = %#v", ledger.Summary)
	}
	if got := ledger.Capabilities[0].Cells["real_stack_proof"].State; got != "gap" {
		t.Fatalf("real_stack_proof state = %q, want gap", got)
	}
}

func TestValidatorRejectsCommentOnlyEvidence(t *testing.T) {
	tests := []struct {
		name       string
		relative   string
		body       string
		cell       string
		mutateCell func(*Capability)
	}{
		{
			name:     "non-REST API anchor",
			relative: "internal/foo/engine.go",
			body:     "package foo\n// tools/list\n",
			cell:     "api",
			mutateCell: func(capability *Capability) {
				capability.API = Cell{Refs: []string{"file:internal/foo/engine.go#tools/list"}}
			},
		},
		{
			name:     "hidden documentation anchor",
			relative: "docs/foo.md",
			body:     "<!-- Fixture capability -->\n",
			cell:     "docs",
			mutateCell: func(capability *Capability) {
				capability.Docs = Cell{Refs: []string{"file:docs/foo.md#Fixture capability"}}
			},
		},
		{
			name:     "hidden configuration key",
			relative: "docs/configuration.md",
			body:     "# Configuration\n<!-- PROBECTL_FOO -->\n",
			cell:     "config_keys",
			mutateCell: func(_ *Capability) {
			},
		},
		{
			name:     "hidden Markdown documentation reference",
			relative: "docs/foo.md",
			body:     "[comment]: <> (Fixture capability)\n",
			cell:     "docs",
			mutateCell: func(capability *Capability) {
				capability.Docs = Cell{Refs: []string{"file:docs/foo.md#Fixture capability"}}
			},
		},
		{
			name:     "hidden Markdown configuration reference",
			relative: "docs/configuration.md",
			body:     "# Configuration\n[comment]: <> (PROBECTL_FOO)\n",
			cell:     "config_keys",
			mutateCell: func(_ *Capability) {
			},
		},
		{
			name:     "comment-only migration",
			relative: "migrations/0001_foo.sql",
			body:     "-- no executable schema statement\n",
			cell:     "migration",
			mutateCell: func(capability *Capability) {
				capability.Migration = Cell{Refs: []string{"file:migrations/0001_foo.sql"}}
			},
		},
		{
			name:     "DDL keyword inside SQL string",
			relative: "migrations/0001_foo.sql",
			body:     "SELECT ' CREATE TABLE decoy';\n",
			cell:     "migration",
			mutateCell: func(capability *Capability) {
				capability.Migration = Cell{Refs: []string{"file:migrations/0001_foo.sql"}}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(tc.relative)), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			tc.mutateCell(&registry.Capabilities[0])
			violations := validator.Validate(registry)
			if !containsViolation(violations, "F1", tc.cell, "invalid-ref") {
				t.Fatalf("violations = %#v; want comment-only %s evidence rejected", violations, tc.cell)
			}
		})
	}
}

func TestExecutableSQLIgnoresCommentsAndQuotedDecoys(t *testing.T) {
	if !containsExecutableSQL([]byte("-- operator's migration\nCREATE TABLE live (id text);\n")) {
		t.Fatal("real CREATE statement was not recognized")
	}
	for _, decoy := range []string{
		"-- CREATE TABLE hidden (id text);\n",
		"SELECT ' CREATE TABLE hidden';\n",
		"SELECT $$ CREATE TABLE hidden $$;\n",
		"BEGIN ; COMMIT ;\n",
	} {
		if containsExecutableSQL([]byte(decoy)) {
			t.Fatalf("quoted/commented SQL decoy was accepted: %q", decoy)
		}
	}
}

func TestValidatorRequiresLiveGoProtocolDispatchAnchor(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		valid bool
	}{
		{
			name:  "reachable dispatch case",
			body:  "package foo\nfunc Handle(method string) { dispatch(method) }\nfunc dispatch(method string) { switch method { case \"tools/list\": run() } }\nfunc run() {}\n",
			valid: true,
		},
		{
			name: "string-only decoy",
			body: "package foo\nfunc Handle() string { return \"tools/list\" }\n",
		},
		{
			name: "constant-dead dispatch case",
			body: "package foo\nfunc Handle() { switch 1 { case 2: run(\"tools/list\") } }\nfunc run(string) {}\n",
		},
		{
			name: "not-equal branch",
			body: "package foo\nfunc Handle(method string) { if method != \"tools/list\" { run() } }\nfunc run() {}\n",
		},
		{
			name: "panic-only dispatch stub",
			body: "package foo\nfunc Handle(method string) { switch method { case \"tools/list\": panic(\"not implemented\") } }\n",
		},
		{
			name: "exported method on unexported receiver",
			body: "package foo\ntype server struct{}\nfunc (server) Handle(method string) { switch method { case \"tools/list\": run() } }\nfunc run() {}\n",
		},
		{
			name: "excluded build file",
			body: "//go:build never\n\npackage foo\nfunc Handle(method string) { switch method { case \"tools/list\": run() } }\nfunc run() {}\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "foo", "engine.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			registry.Capabilities[0].API = Cell{Refs: []string{"file:internal/foo/engine.go#tools/list"}}
			violations := validator.Validate(registry)
			invalid := containsViolation(violations, "F1", "api", "invalid-ref")
			if tc.valid && invalid {
				t.Fatalf("violations = %#v; want live protocol dispatch accepted", violations)
			}
			if !tc.valid && !invalid {
				t.Fatalf("violations = %#v; want protocol decoy rejected", violations)
			}
		})
	}
}

func TestValidatorRejectsUnparsedNonRESTAPIEvidence(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "foo", "protocol.txt")
	if err := os.WriteFile(path, []byte("tools/list is not implemented\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].API = Cell{Refs: []string{"file:internal/foo/protocol.txt#tools/list"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "api", "invalid-ref") {
		t.Fatalf("violations = %#v; want unparsed non-REST API evidence rejected", violations)
	}
}

func TestValidatorRejectsProtocolReachabilityAcrossInvalidPackageBoundary(t *testing.T) {
	root := fixtureRepo(t)
	enginePath := filepath.Join(root, "internal", "foo", "engine.go")
	if err := os.WriteFile(enginePath, []byte("package foo\nfunc Handle() { dispatch() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(root, "internal", "foo", "other.go")
	if err := os.WriteFile(otherPath, []byte("package other\nfunc dispatch() { run(\"tools/list\") }\nfunc run(string) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].API = Cell{Refs: []string{"file:internal/foo/engine.go#tools/list"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "api", "invalid-ref") {
		t.Fatalf("violations = %#v; want mixed-package protocol evidence rejected", violations)
	}
}

func TestValidatorPrecomputesVisibleConfigurationDocument(t *testing.T) {
	root := fixtureRepo(t)
	configuration := "# Configuration\nPROBECTL_FOO\n<!-- PROBECTL_HIDDEN -->\n[comment]: <> (PROBECTL_REFERENCE_HIDDEN)\n"
	if err := os.WriteFile(filepath.Join(root, "docs", "configuration.md"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	if !containsVisibleConfigKey(validator.configDocVisible, "PROBECTL_FOO") {
		t.Fatal("visible configuration key was not indexed")
	}
	if !validator.configKeys["PROBECTL_FOO"] {
		t.Fatal("validator did not retain the exact visible-key index")
	}
	for _, hidden := range []string{"PROBECTL_HIDDEN", "PROBECTL_REFERENCE_HIDDEN"} {
		if containsVisibleConfigKey(validator.configDocVisible, hidden) || validator.configKeys[hidden] {
			t.Fatalf("hidden configuration key %s became visible", hidden)
		}
	}
	for _, substring := range []string{"PROBECTL_FO", "XPROBECTL_FOO", "PROBECTL_FOO_EXTRA"} {
		if validator.configKeys[substring] {
			t.Fatalf("non-exact configuration key %s became visible", substring)
		}
	}
}

func fixtureRegistry() Registry {
	return Registry{
		Schema:        RegistrySchema,
		SourceCatalog: "docs/claims/release-catalog.json",
		Capabilities: []Capability{{
			ID: "F1", Name: "Fixture capability", Status: "delivered", Owner: "fixture/owner",
			Engine:         Cell{Refs: []string{"file:internal/foo/engine.go"}},
			Binary:         Cell{Refs: []string{"file:cmd/foo/main.go#func BuildFoo"}},
			API:            Cell{Refs: []string{"api:GET /v1/foo"}},
			CLI:            Cell{Refs: []string{"cli:probectl test list"}},
			UI:             Cell{Refs: []string{"ui:F1@/foo"}},
			Docs:           Cell{Refs: []string{"file:docs/foo.md#Fixture capability"}},
			ConfigKeys:     Cell{Refs: []string{"config:PROBECTL_FOO"}},
			Telemetry:      Cell{Refs: []string{"file:internal/otel/foo.go"}},
			RealStackProof: Cell{Refs: []string{"test:test/integration/foo_integration_test.go#TestFooRealStack"}},
			Migration:      Cell{NoneByDesign: "The capability owns no schema and therefore needs no migration."},
		}},
	}
}

func cloneRegistry(t *testing.T, registry Registry) Registry {
	t.Helper()
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	var out Registry
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func containsViolation(violations []Violation, capability, cell, code string) bool {
	for _, violation := range violations {
		if violation.Capability == capability && violation.Cell == cell && violation.Code == code {
			return true
		}
	}
	return false
}

func fixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	genericSource, err := os.ReadFile(filepath.Join("..", "cli", "generic.go"))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"internal/control/openapi.json":                `{"paths":{"/v1/foo":{"get":{"responses":{}}}}}`,
		"internal/control/server.go":                   "package control\nfunc New() { s.foo = buildFoo }\n",
		"ee/provider/openapi.json":                     `{"paths":{}}`,
		"web/src/surfaces.ts":                          "export const SURFACES = [\n  {\n    featureIds: ['F1'],\n    kind: 'native',\n    route: '/foo',\n  },\n  {\n    featureIds: ['F2'],\n    kind: 'native',\n    route: '/bar',\n  },\n]\n",
		"docs/configuration.md":                        "# Configuration\nPROBECTL_FOO\n",
		"docs/claims/release-catalog.json":             `{"schema":"probectl.release-claim-catalog/v1","purpose":"Fixture catalog for completeness validation.","claims":[{"id":"F1","kind":"capability","owner":"fixture/owner"}]}`,
		"docs/claims/completeness-denominator.json":    `{"schema":"probectl.completeness-denominator/v1","feature_range":{"prefix":"F","first":1,"last":1},"governed_claims":[]}`,
		"docs/claims/completeness-none-by-design.json": `{"schema":"probectl.completeness-none-by-design/v1","cells":["F1.migration"]}`,
		"test/real-stack-proofs.json":                  `{"schema":"probectl.real-stack-proofs/v1","proofs":[{"ref":"test:test/integration/foo_integration_test.go#TestFooRealStack","profile":"integration","capabilities":["F1"]}]}`,
		"Makefile":                                     "GO ?= go\nGO_MODULE_DIRS := . test\n\ntest-integration:\n\t@./scripts/with_integration_stack_lock.sh integration bash -c 'set -e; for d in $(GO_MODULE_DIRS); do \\\n\t\t( cd $$d && $(GO) test -tags=integration ./... ) || exit 1; \\\n\tdone'\n",
		"scripts/with_integration_stack_lock.sh":       "#!/usr/bin/env bash\nset -e\nshift\n\"$@\"\n",
		".github/workflows/ci.yml":                     "jobs:\n  integration:\n    steps:\n      - run: make test-integration\n",
		"internal/foo/engine.go":                       "package foo\nfunc Run() int { return 1 }\n",
		"internal/foo/foo_test.go":                     "package foo\nimport \"testing\"\nfunc TestUnrelatedUnit(t *testing.T) {}\n",
		"internal/cli/commands.go":                     "package cli\nfunc cmdTest(cfg int, args []string, stdout, stderr int) int { if len(args) == 0 { fmt.Fprintln(stderr, \"test: expected a subcommand (list|get|create|delete|path|path-history)\"); return 2 }; c := newClient(cfg); switch args[0] { case \"list\": return runRawOperation() } }\nfunc cmdAgent(cfg int, args []string, stdout, stderr int) int { if len(args) == 0 { fmt.Fprintln(stderr, \"agent: expected a subcommand (list|get|delete)\"); return 2 }; c := newClient(cfg); switch args[0] { case \"list\": return runRawOperation() } }\nfunc cmdLifecycle(cfg int, args []string, stdout, stderr int) int { return cmdSurface(cfg, surfaceCommands[\"lifecycle\"], args, stdout, stderr) }\n",
		"internal/cli/cli.go":                          "package cli\nfunc RunWithStdin(args []string) int { cfg := Config{ BaseURL: envOr(getenv, \"PROBECTL_API_URL\", \"https://localhost:8443\"), Token: getenv(\"PROBECTL_API_TOKEN\"), Tenant: getenv(\"PROBECTL_TENANT\"), Locale: i18n.Resolve(getenv(\"PROBECTL_LOCALE\")), SessionCookieFile: getenv(\"PROBECTL_SESSION_COOKIE_FILE\"), CAFile: getenv(\"PROBECTL_CA_FILE\") }; args, cfg.JSON = extractBoolFlag(args, \"--json\"); if len(args) == 1 && (args[0] == \"-h\" || args[0] == \"--help\") { usage(stdout, cfg.Locale); return 0 }; fs := flag.NewFlagSet(\"probectl\", flag.ContinueOnError); fs.SetOutput(stderr); fs.Usage = func() { usage(stderr, cfg.Locale) }; fs.StringVar(&cfg.BaseURL, \"url\", cfg.BaseURL, \"control-plane API base URL (env PROBECTL_API_URL)\"); fs.StringVar(&cfg.Token, \"token\", cfg.Token, \"API auth token, sent as Bearer (env PROBECTL_API_TOKEN)\"); fs.StringVar(&cfg.Tenant, \"tenant\", cfg.Tenant, \"tenant UUID, sent as X-Probectl-Tenant (env PROBECTL_TENANT)\"); fs.StringVar(&cfg.CAFile, \"ca-file\", cfg.CAFile, \"PEM CA bundle that verifies the control plane's certificate (env PROBECTL_CA_FILE); default: the OS trust store\"); if err := fs.Parse(args); err != nil { return 2 }; rest := fs.Args(); if len(rest) == 0 { return 2 }; switch rest[0] { case \"test\": return cmdTest(cfg, rest[1:], stdout, stderr); case \"agent\": return cmdAgent(cfg, rest[1:], stdout, stderr); case \"lifecycle\": return cmdLifecycle(cfg, rest[1:], stdout, stderr); default: if spec, ok := surfaceCommands[rest[0]]; ok { return cmdSurfaceWithStdin(cfg, spec, rest[1:], stdin, stdout, stderr) }; return 2 } }\n",
		"internal/cli/generic.go":                      string(genericSource),
		"cmd/foo/main.go":                              "package main\nfunc main() { BuildFoo() }\nfunc BuildFoo() {}\n",
		"cmd/probectl-control/main.go":                 "package main\nfunc main() { runServe() }\n",
		"cmd/probectl-control/serve_runtime.go":        "package main\nfunc runServe() { control.New() }\n",
		"docs/foo.md":                                  "# Fixture capability\n",
		"internal/otel/foo.go":                         "package otel\ntype ProbeResult struct { Success bool; Latency int }\n",
		"test/integration/foo_integration_test.go":     "//go:build integration\n\npackage integration\nimport \"testing\"\nfunc TestFooRealStack(t *testing.T) { t.Setenv(\"PROBECTL_FIXTURE_PROOF\", \"executed\") }\n",
		"migrations/0001_foo.sql":                      "CREATE TABLE IF NOT EXISTS foo (id TEXT);\n",
	}
	files["internal/cli/commands.go"] += "\nfunc testCreate(cfg, c int, args []string, stdout, stderr int) int " + specialCLICalleeSpines["testCreate"] + "\n"
	for relative, body := range files {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
