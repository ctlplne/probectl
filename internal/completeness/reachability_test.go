// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"go/parser"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConstantBooleanUsesGoConstantSemantics(t *testing.T) {
	tests := []struct {
		expression string
		want       bool
		constant   bool
	}{
		{expression: "1 == 2", want: false, constant: true},
		{expression: "1 + 1 == 2", want: true, constant: true},
		{expression: `len("probe") == 5`, want: true, constant: true},
		{expression: "runtimeCondition", constant: false},
	}
	for _, tc := range tests {
		t.Run(tc.expression, func(t *testing.T) {
			expression, err := parser.ParseExpr(tc.expression)
			if err != nil {
				t.Fatal(err)
			}
			got, constant := constantBoolean(expression)
			if got != tc.want || constant != tc.constant {
				t.Fatalf("constantBoolean(%q) = (%t, %t), want (%t, %t)", tc.expression, got, constant, tc.want, tc.constant)
			}
		})
	}
}

func TestValidatorRejectsDeadBinaryFunction(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "cmd", "foo", "main.go")
	writeFixtureMutation(t, path, "func main() { BuildFoo() }", "func main() {}")
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := validator.Validate(fixtureRegistry())
	if !containsViolation(violations, "F1", "binary", "invalid-ref") {
		t.Fatalf("violations = %#v; want dead binary function rejection", violations)
	}
}

func TestValidatorRejectsControlFlowAndScopeReachabilityDecoys(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "dead scope cannot relabel receiver",
			body: `package main
type live struct{}
type dead struct{}
func main() { x := &dead{}; if false { x := &live{}; _ = x }; x.Run() }
func (x *live) Run() { BuildFoo() }
func (x *dead) Run() {}
func BuildFoo() {}
`,
		},
		{
			name: "constant dead switch",
			body: "package main\nfunc main() { switch 1 { case 2: BuildFoo() } }\nfunc BuildFoo() {}\n",
		},
		{
			name: "goto skipped call",
			body: "package main\nfunc main() { goto done; BuildFoo(); done: }\nfunc BuildFoo() {}\n",
		},
		{
			name: "named false constant",
			body: "package main\nconst enabled = false\nfunc main() { if enabled { BuildFoo() } }\nfunc BuildFoo() {}\n",
		},
		{
			name: "guaranteed return",
			body: "package main\nfunc main() { if true { return }; BuildFoo() }\nfunc BuildFoo() {}\n",
		},
		{
			name: "short circuited call",
			body: "package main\nfunc main() { _ = false && BuildFoo() }\nfunc BuildFoo() bool { return true }\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "cmd", "foo", "main.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			violations := validator.Validate(fixtureRegistry())
			if !containsViolation(violations, "F1", "binary", "invalid-ref") {
				t.Fatalf("violations = %#v; want unreachable binary rejection", violations)
			}
		})
	}
}

func TestValidatorRejectsCommentOnlyBinaryAnchor(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "cmd", "foo", "main.go")
	writeFixtureMutation(t, path, "func main() { BuildFoo() }", "func main() { BuildFoo() /* realAssembly() */ }")
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Binary = Cell{Refs: []string{"file:cmd/foo/main.go#realAssembly("}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "binary", "invalid-ref") {
		t.Fatalf("violations = %#v; want comment-only binary anchor rejection", violations)
	}
}

func TestValidatorDoesNotTreatSameNamedLocalOrImportedSelectorAsReachability(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "same-named local", body: "package main\nfunc main() { BuildFoo := false; _ = BuildFoo }\nfunc BuildFoo() {}\n"},
		{name: "imported selector", body: "package main\nimport other \"example.invalid/other\"\nfunc main() { other.BuildFoo() }\nfunc BuildFoo() {}\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "cmd", "foo", "main.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			violations := validator.Validate(fixtureRegistry())
			if !containsViolation(violations, "F1", "binary", "invalid-ref") {
				t.Fatalf("violations = %#v; want false reachability rejection", violations)
			}
		})
	}
}

func TestValidatorDoesNotTreatUnusedFunctionValueAsReachability(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "cmd", "foo", "main.go")
	body := "package main\nfunc main() { callback := BuildFoo; _ = callback }\nfunc BuildFoo() {}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := validator.Validate(fixtureRegistry())
	if !containsViolation(violations, "F1", "binary", "invalid-ref") {
		t.Fatalf("violations = %#v; want unused function value rejection", violations)
	}
}

func TestValidatorIgnoresExcludedBuildConstraintFiles(t *testing.T) {
	root := fixtureRepo(t)
	mainPath := filepath.Join(root, "cmd", "foo", "main.go")
	if err := os.WriteFile(mainPath, []byte("package main\nfunc main() {}\nfunc BuildFoo() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	excluded := filepath.Join(root, "cmd", "foo", "excluded.go")
	if err := os.WriteFile(excluded, []byte("//go:build never\n\npackage main\nfunc init() { BuildFoo() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := validator.Validate(fixtureRegistry())
	if !containsViolation(violations, "F1", "binary", "invalid-ref") {
		t.Fatalf("violations = %#v; want excluded build-file rejection", violations)
	}
}

func TestValidatorRejectsStringLiteralDecoyForBinaryAnchor(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "cmd", "foo", "main.go")
	body := "package main\nfunc main() { println(\"BuildFoo(\") }\nfunc BuildFoo() {}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Binary = Cell{Refs: []string{"file:cmd/foo/main.go#BuildFoo("}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "binary", "invalid-ref") {
		t.Fatalf("violations = %#v; want string-literal decoy rejection", violations)
	}
}

func TestValidatorRequiresExecutableCallContextForBinaryAnchor(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "blank assignment", body: "package main\nfunc main() { _ = BuildFoo }\nfunc BuildFoo() {}\n"},
		{name: "constant false call", body: "package main\nfunc main() { if false { BuildFoo() } }\nfunc BuildFoo() {}\n"},
		{name: "constant comparison false call", body: "package main\nfunc main() { if 1 == 2 { BuildFoo() } }\nfunc BuildFoo() {}\n"},
		{name: "constant arithmetic false call", body: "package main\nfunc main() { if 1 + 1 != 2 { BuildFoo() } }\nfunc BuildFoo() {}\n"},
		{name: "constant true excludes else call", body: "package main\nfunc main() { if 2 > 1 {} else { BuildFoo() } }\nfunc BuildFoo() {}\n"},
		{name: "constant true excludes else-if call", body: "package main\nfunc main() { if 2 > 1 {} else if runtimeCondition() { BuildFoo() } }\nfunc runtimeCondition() bool { return true }\nfunc BuildFoo() {}\n"},
		{name: "call after return", body: "package main\nfunc main() { return; BuildFoo() }\nfunc BuildFoo() {}\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "cmd", "foo", "main.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			registry.Capabilities[0].Binary = Cell{Refs: []string{"file:cmd/foo/main.go#BuildFoo("}}
			violations := validator.Validate(registry)
			if !containsViolation(violations, "F1", "binary", "invalid-ref") {
				t.Fatalf("violations = %#v; want non-executable anchor rejection", violations)
			}
		})
	}
}

func TestValidatorRequiresExactAssemblyCallCalleeAndArguments(t *testing.T) {
	const declarations = `
type registry struct{}
func (registry) Register(string, func()) {}
var reg registry
var other registry
type factories struct { NewNoop func() }
var canary factories
`
	tests := []struct {
		name  string
		body  string
		valid bool
	}{
		{
			name:  "exact registration",
			body:  "package main\n" + declarations + `func main() { reg.Register("noop", canary.NewNoop) }`,
			valid: true,
		},
		{
			name: "factory only passed to unrelated call",
			body: "package main\nimport \"fmt\"\n" + declarations + `func main() { _ = fmt.Sprint(canary.NewNoop) }`,
		},
		{
			name: "wrong registration name",
			body: "package main\n" + declarations + `func main() { reg.Register("icmp", canary.NewNoop) }`,
		},
		{
			name: "wrong registry callee",
			body: "package main\n" + declarations + `func main() { other.Register("noop", canary.NewNoop) }`,
		},
		{
			name: "raw string decoy",
			body: "package main\nimport \"fmt\"\n" + declarations + "func main() { _ = fmt.Sprint(`reg.Register(\"noop\", canary.NewNoop)`) }",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "cmd", "foo", "main.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			registry.Capabilities[0].Binary = Cell{Refs: []string{`file:cmd/foo/main.go#reg.Register("noop", canary.NewNoop)`}}
			violations := validator.Validate(registry)
			invalid := containsViolation(violations, "F1", "binary", "invalid-ref")
			if tc.valid && invalid {
				t.Fatalf("violations = %#v; want exact assembly call accepted", violations)
			}
			if !tc.valid && !invalid {
				t.Fatalf("violations = %#v; want assembly call callee/argument mismatch rejected", violations)
			}
		})
	}
}

func TestValidatorRequiresExactBinaryAnchorTokens(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		anchor string
		valid  bool
	}{
		{
			name:   "exact assignment",
			body:   "package main\nvar target any\nfunc main() { target = BuildFoo }\nfunc BuildFoo() {}\n",
			anchor: "target = BuildFoo",
			valid:  true,
		},
		{
			name:   "assignment suffix decoy",
			body:   "package main\nvar target any\nfunc main() { target = BuildFooDecoy }\nfunc BuildFooDecoy() {}\n",
			anchor: "target = BuildFoo",
		},
		{
			name:   "exact bare selector",
			body:   "package main\ntype server struct{ handleGetHierarchy func() }\nvar s server\nfunc main() { register(s.handleGetHierarchy) }\nfunc register(func()) {}\n",
			anchor: "s.handleGetHierarchy",
			valid:  true,
		},
		{
			name:   "bare selector suffix decoy",
			body:   "package main\ntype server struct{ handleGetHierarchyDecoy func() }\nvar s server\nfunc main() { register(s.handleGetHierarchyDecoy) }\nfunc register(func()) {}\n",
			anchor: "s.handleGetHierarchy",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "cmd", "foo", "main.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			registry.Capabilities[0].Binary = Cell{Refs: []string{"file:cmd/foo/main.go#" + tc.anchor}}
			violations := validator.Validate(registry)
			invalid := containsViolation(violations, "F1", "binary", "invalid-ref")
			if invalid == tc.valid {
				t.Fatalf("violations = %#v; valid = %t", violations, tc.valid)
			}
		})
	}
}

func TestValidatorResolvesMethodReceiverIdentity(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "cmd", "foo", "main.go")
	body := `package main
type live struct{}
type dead struct{}
func main() { x := &live{}; x.Run() }
func (x *live) Run() {}
func (x *dead) Run() { deadAssembly() }
func deadAssembly() {}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].Binary = Cell{Refs: []string{"file:cmd/foo/main.go#func deadAssembly"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "binary", "invalid-ref") {
		t.Fatalf("violations = %#v; want receiver-specific reachability rejection", violations)
	}
}

func TestValidatorRejectsCrossFileAndTerminalReachabilityDecoys(t *testing.T) {
	tests := []struct {
		name       string
		mainSource string
		extraFile  string
		extraBody  string
	}{
		{
			name:       "cross-file named false constant",
			mainSource: "package main\nfunc main() { if enabled { BuildFoo() } }\nfunc BuildFoo() {}\n",
			extraFile:  "flags.go",
			extraBody:  "package main\nconst enabled = false\n",
		},
		{
			name:       "call after break",
			mainSource: "package main\nfunc main() { for { break; BuildFoo() } }\nfunc BuildFoo() {}\n",
		},
		{
			name:       "call after builtin panic",
			mainSource: "package main\nfunc main() { panic(\"stop\"); BuildFoo() }\nfunc BuildFoo() {}\n",
		},
		{
			name:       "call after selected constant-switch return",
			mainSource: "package main\nfunc main() { switch 1 { case 1: return }; BuildFoo() }\nfunc BuildFoo() {}\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			commandDir := filepath.Join(root, "cmd", "foo")
			if err := os.WriteFile(filepath.Join(commandDir, "main.go"), []byte(tc.mainSource), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.extraFile != "" {
				if err := os.WriteFile(filepath.Join(commandDir, tc.extraFile), []byte(tc.extraBody), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			violations := validator.Validate(fixtureRegistry())
			if !containsViolation(violations, "F1", "binary", "invalid-ref") {
				t.Fatalf("violations = %#v; want dead reachability decoy rejected", violations)
			}
		})
	}
}

func writeFixtureMutation(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(data), old, replacement, 1)
	if mutated == string(data) {
		t.Fatalf("mutation did not find %q", old)
	}
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
}
