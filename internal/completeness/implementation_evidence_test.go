// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImplementationEvidenceRejectsNonProductionDecoys(t *testing.T) {
	tests := []struct {
		name    string
		cell    string
		path    string
		files   map[string]string
		problem string
	}{
		{
			name: "comment-only Go engine",
			cell: "engine", path: "internal/commentonly", problem: "no non-test production declaration",
			files: map[string]string{"doc.go": "package commentonly\n// func Run() { doWork() }\n"},
		},
		{
			name: "package-only doc.go",
			cell: "engine", path: "internal/packageonly", problem: "no non-test production declaration",
			files: map[string]string{"doc.go": "// Package packageonly documents a future engine.\npackage packageonly\n"},
		},
		{
			name: "empty Go engine type",
			cell: "engine", path: "internal/emptyengine", problem: "no non-test production declaration",
			files: map[string]string{"engine.go": "package emptyengine\ntype Engine struct{}\n"},
		},
		{
			name: "panic-only Go engine stub",
			cell: "engine", path: "internal/panicstub", problem: "no non-test production declaration",
			files: map[string]string{"engine.go": "package panicstub\nfunc Run() { panic(\"not implemented\") }\n"},
		},
		{
			name: "test-only directory",
			cell: "engine", path: "internal/testonly", problem: "no non-test production declaration",
			files: map[string]string{"engine_test.go": "package testonly\nfunc TestEngine() { run() }\n"},
		},
		{
			name: "direct test file",
			cell: "engine", path: "internal/direct/engine_test.go", problem: "points to a test file",
			files: map[string]string{"internal/direct/engine_test.go": "package direct\nfunc TestEngine() { run() }\n"},
		},
		{
			name: "excluded Go build",
			cell: "engine", path: "internal/buildnever", problem: "no non-test production declaration",
			files: map[string]string{"engine.go": "//go:build never\n\npackage buildnever\nfunc Run() int { return 1 }\n"},
		},
		{
			name: "telemetry named only in comments",
			cell: "telemetry", path: "internal/commenttelemetry", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal.go": "package commenttelemetry\n// logger.Info(\"sent metric\")\nfunc Run() {}\n"},
		},
		{
			name: "telemetry named only in a string",
			cell: "telemetry", path: "internal/stringtelemetry", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal.go": "package stringtelemetry\nfunc Run() string { return `logger.Info(\"sent metric\")` }\n"},
		},
		{
			name: "telemetry only in a test",
			cell: "telemetry", path: "internal/testtelemetry", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal_test.go": "package testtelemetry\nfunc TestSignal() { logger.Info(\"sent metric\") }\n"},
		},
		{
			name: "empty telemetry-named type",
			cell: "telemetry", path: "internal/emptytype", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal.go": "package emptytype\ntype Metric struct{}\n"},
		},
		{
			name: "telemetry-named scalar variable",
			cell: "telemetry", path: "internal/nameonly", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal.go": "package nameonly\nvar metric = \"decoy\"\nfunc Run() {}\n"},
		},
		{
			name: "generic event type name",
			cell: "telemetry", path: "internal/genericevent", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal.go": "package genericevent\ntype Event struct { Name string }\n"},
		},
		{
			name: "no-argument report call",
			cell: "telemetry", path: "internal/noopreport", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal.go": "package noopreport\nfunc Run() { Report() }\nfunc Report() {}\n"},
		},
		{
			name: "argument-only report name",
			cell: "telemetry", path: "internal/namedreport", problem: "no production signal/log/metric/OTel emission",
			files: map[string]string{"signal.go": "package namedreport\nfunc Run() { Report(1) }\nfunc Report(int) {}\n"},
		},
		{
			name: "JavaScript comment decoy",
			cell: "engine", path: "internal/jscomment", problem: "no non-test production declaration",
			files: map[string]string{"worker.mjs": "// function run() { return true; }\n/* const engine = start(); */\n"},
		},
		{
			name: "Python comment and docstring decoy",
			cell: "engine", path: "analyzer/pythoncomment", problem: "no non-test production declaration",
			files: map[string]string{"worker.py": "# def run(): return True\n'''class Engine:\n    pass\n'''\n"},
		},
		{
			name: "Terraform comment decoy",
			cell: "engine", path: "deploy/terraform-comment", problem: "no non-test production declaration",
			files: map[string]string{"main.tf": "# resource \"fake\" \"engine\" {}\n// module \"fake\" {}\n/* data \"fake\" \"engine\" {} */\n"},
		},
		{
			name: "YAML comment decoy",
			cell: "engine", path: "deploy/gitops-comment", problem: "no non-test production declaration",
			files: map[string]string{"application.yaml": "# apiVersion: fake/v1\n# kind: Application\n# spec: {}\n"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := implementationFixtureRoot(t)
			for relative, body := range tc.files {
				if !strings.Contains(relative, "/") {
					relative = filepath.Join(tc.path, relative)
				}
				writeImplementationFixture(t, root, relative, body)
			}
			validator := &Validator{root: root}
			err := validator.validateImplementationEvidence(tc.cell, tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.problem) {
				t.Fatalf("error = %v, want problem containing %q", err, tc.problem)
			}
		})
	}
}

func TestImplementationEvidenceAcceptsProductionSyntax(t *testing.T) {
	tests := []struct {
		name string
		cell string
		path string
		body string
	}{
		{name: "Go function body", cell: "engine", path: "internal/goengine/engine.go", body: "package goengine\nfunc Run() int { return 1 }\n"},
		{name: "Go type declaration", cell: "engine", path: "internal/gomodel/model.go", body: "package gomodel\ntype Engine struct { Enabled bool }\n"},
		{name: "Python function", cell: "engine", path: "analyzer/worker.py", body: "def run():\n    return 1\n"},
		{name: "JavaScript function", cell: "engine", path: "browser-worker/worker.mjs", body: "export function run() { return true; }\n"},
		{name: "Terraform block", cell: "engine", path: "deploy/terraform/main.tf", body: "resource \"kubernetes_namespace\" \"probectl\" {\n  metadata { name = \"probectl\" }\n}\n"},
		{name: "Kubernetes object", cell: "engine", path: "deploy/gitops/application.yaml", body: "apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  project: default\n"},
		{name: "Go structured log", cell: "telemetry", path: "internal/logsignal/signal.go", body: "package logsignal\nimport \"log/slog\"\nfunc Report() { slog.Info(\"ready\", \"tenant_id\", \"t1\") }\n"},
		{name: "Go telemetry model", cell: "telemetry", path: "internal/result/model.go", body: "package result\nimport \"time\"\ntype ProbeResult struct { Success bool; Latency time.Duration }\n"},
		{name: "Go health model", cell: "telemetry", path: "internal/health/model.go", body: "package health\ntype BackendHealth struct { Configured bool; Failures int }\n"},
		{name: "Go event callback", cell: "telemetry", path: "internal/callback/model.go", body: "package callback\ntype Limiter struct { OnLockout func(string) }\n"},
		{name: "Go audit append", cell: "telemetry", path: "internal/auditsignal/signal.go", body: "package auditsignal\nfunc Rotate(ctx Context) error { return audit.TenantAppend(ctx) }\n"},
		{name: "Go signal result", cell: "telemetry", path: "internal/synthesis/signal.go", body: "package synthesis\ntype Synthesis struct { Count int; Error string }\nfunc Build() Synthesis { return Synthesis{} }\n"},
		{name: "Python structured log", cell: "telemetry", path: "internal/pysignal/signal.py", body: "def report(log):\n    log.info(\"ready\", tenant_id=\"t1\")\n"},
		{name: "JavaScript metric emission", cell: "telemetry", path: "internal/jssignal/signal.mjs", body: "export function report(metrics) { metrics.emit('ready', 1); }\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := implementationFixtureRoot(t)
			writeImplementationFixture(t, root, tc.path, tc.body)
			validator := &Validator{root: root}
			if err := validator.validateImplementationEvidence(tc.cell, tc.path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func writeImplementationFixture(t *testing.T, root, relative, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func implementationFixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
