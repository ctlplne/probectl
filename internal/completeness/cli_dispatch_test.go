// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExactCLIHandlerSpinesMatchShippingSources(t *testing.T) {
	for _, relative := range []string{"../cli/ai.go", "../cli/commands.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), relative, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			want, tracked := customCLIHandlerSpines[fn.Name.Name]
			if !tracked {
				want, tracked = specialCLICalleeSpines[fn.Name.Name]
			}
			if !tracked {
				continue
			}
			got, ok := canonicalGoBody(fn.Body)
			if !ok {
				t.Fatalf("canonicalize %s", fn.Name.Name)
			}
			if got != want {
				t.Fatalf("%s canonical spine drifted\n--- got ---\n%s\n--- want ---\n%s", fn.Name.Name, got, want)
			}
		}
	}
}

func TestCLIRunPreludeSpineMatchesShippingSource(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "../cli/cli.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "RunWithStdin" || fn.Body == nil || len(fn.Body.List) < 3 {
			continue
		}
		got, ok := canonicalGoStatements(fn.Body.List[:len(fn.Body.List)-3])
		if !ok {
			t.Fatal("canonicalize RunWithStdin prelude")
		}
		if got != cliRunPreludeSpine {
			t.Fatalf("RunWithStdin canonical prelude drifted\n--- got ---\n%s\n--- want ---\n%s", got, cliRunPreludeSpine)
		}
		return
	}
	t.Fatal("RunWithStdin not found")
}

func TestValidatorTracksActualTopLevelCLIDispatch(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{name: "case removed", old: `case "test":`, replacement: `case "deleted-test":`},
		{name: "delegate removed", old: `return cmdTest(cfg, rest[1:], stdout, stderr)`, replacement: `return 2`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "cli", "cli.go")
			mutateCLIAndAddDecoyComment(t, path, tc.old, tc.replacement)
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			violations := validator.Validate(fixtureRegistry())
			if !containsViolation(violations, "F1", "cli", "invalid-ref") {
				t.Fatalf("violations = %#v; want top-level CLI disconnection rejection", violations)
			}
		})
	}
}

func TestValidatorTracksActualGenericCLIDispatch(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{name: "wrong catalog", old: `surfaceCommands[rest[0]]`, replacement: `otherCommands[rest[0]]`},
		{name: "wrong index", old: `surfaceCommands[rest[0]]`, replacement: `surfaceCommands["bgp"]`},
		{name: "delegate removed", old: `return cmdSurface(cfg, spec, rest[1:], stdout, stderr)`, replacement: `return 2`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "cli", "cli.go")
			mutateCLIAndAddDecoyComment(t, path, tc.old, tc.replacement)
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl bgp events"}}
			violations := validator.Validate(registry)
			if !containsViolation(violations, "F1", "cli", "invalid-ref") {
				t.Fatalf("violations = %#v; want generic CLI disconnection rejection", violations)
			}
		})
	}
}

func TestExplicitDeadCaseCannotFallThroughToGenericDispatcher(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "cli.go")
	mutateCLIAndAddDecoyComment(t, path, `return cmdLifecycle(cfg, rest[1:], stdout, stderr)`, `return 2`)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl lifecycle retention"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want shadowing dead case rejection", violations)
	}
}

func TestExplicitHandlerMustReachSurfaceDispatcher(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "commands.go")
	writeFixtureMutation(t, path,
		`return cmdSurface(cfg, surfaceCommands["lifecycle"], args, stdout, stderr)`,
		`return 2`,
	)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl lifecycle retention"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want disconnected explicit handler rejection", violations)
	}
}

func TestExplicitHandlerCannotShadowOneAdvertisedOperation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		old         string
		replacement string
	}{
		{
			name:        "early return",
			old:         `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int {`,
			replacement: `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int { if len(args) > 0 && args[0] == "retention" { return 2 };`,
		},
		{
			name:        "argument rewrite",
			old:         `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int {`,
			replacement: `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int { if len(args) > 0 && args[0] == "retention" { args[0] = "deleted" };`,
		},
		{
			name:        "caller config rewrite",
			old:         `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int {`,
			replacement: `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int { if cfg == 1 { cfg = 0 };`,
		},
		{
			name:        "argument cleared by side effect",
			old:         `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int {`,
			replacement: `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int { if len(args) > 0 && args[0] == "retention" { clear(args) };`,
		},
		{
			name:        "argument rewritten through slice alias",
			old:         `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int {`,
			replacement: `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int { shadow := args; if cfg == 1 { shadow[0] = "deleted" };`,
		},
		{
			name:        "surface binding rewrite",
			old:         `return cmdSurface(cfg, surfaceCommands["lifecycle"], args, stdout, stderr)`,
			replacement: `spec := surfaceCommands["lifecycle"]; spec = surfaceCommands["other"]; return cmdSurface(cfg, spec, args, stdout, stderr)`,
		},
		{
			name:        "surface binding field rewrite",
			old:         `return cmdSurface(cfg, surfaceCommands["lifecycle"], args, stdout, stderr)`,
			replacement: `spec := surfaceCommands["lifecycle"]; if cfg == 1 { spec.Ops = surfaceCommands["other"].Ops }; return cmdSurface(cfg, spec, args, stdout, stderr)`,
		},
		{
			name:        "surface dispatcher locally shadowed",
			old:         `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int {`,
			replacement: `func cmdLifecycle(cfg int, args []string, stdout, stderr int) int { cmdSurface := func(cfg, spec, args, stdout, stderr int) int { return 2 };`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "cli", "commands.go")
			writeFixtureMutation(t, path, tc.old, tc.replacement)
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl lifecycle retention"}}
			violations := validator.Validate(registry)
			if !containsViolation(violations, "F1", "cli", "invalid-ref") {
				t.Fatalf("violations = %#v; want operation-specific shadow rejection", violations)
			}
		})
	}
}

func TestExplicitCustomOperationCannotUseALocalCalleeSpoof(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "commands.go")
	writeFixtureMutation(t, path,
		`return cmdSurface(cfg, surfaceCommands["lifecycle"], args, stdout, stderr)`,
		`cmdLifecycleExport := lifecycleSubjectExport; return cmdLifecycleExport(cfg, args[1:], stdout, stderr)`,
	)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl lifecycle export"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want local custom-callee spoof rejection", violations)
	}
}

func TestExplicitCustomOperationCalleeMustExecuteRequest(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "commands.go")
	writeFixtureMutation(t, path,
		`return cmdSurface(cfg, surfaceCommands["lifecycle"], args, stdout, stderr)`,
		`c := newClient(cfg); return lifecycleExport(c, args[1:], stdout, stderr)`,
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(`
func lifecycleExport(c int, args []string, stdout, stderr int) int {
	return 2
	if err := c.stream("GET", "/v1/lifecycle/export"); err != nil { return 1 }
	return 0
}
`)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl lifecycle export"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want dead custom request callee rejection", violations)
	}
}

func TestExplicitCustomOperationPreservesCallerConfig(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "commands.go")
	writeFixtureMutation(t, path,
		`return cmdSurface(cfg, surfaceCommands["lifecycle"], args, stdout, stderr)`,
		`c := newClient(wrongConfig); return lifecycleExport(c, args[1:], stdout, stderr)`,
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(`
func lifecycleExport(c int, args []string, stdout, stderr int) int {
	if err := c.stream("GET", "/v1/lifecycle/export"); err != nil { return 1 }
	return 0
}
`)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl lifecycle export"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want custom operation caller-config rejection", violations)
	}
}

func TestExplicitCustomOperationPreservesClientInsideCallee(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantReject bool
	}{
		{name: "canonical handler", body: customCLIHandlerSpines["lifecycleExport"]},
		{
			name:       "client config erased",
			body:       strings.Replace(customCLIHandlerSpines["lifecycleExport"], "{", "{\n\tc.cfg = Config{}", 1),
			wantReject: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "cli", "commands.go")
			writeFixtureMutation(t, path,
				`return cmdSurface(cfg, surfaceCommands["lifecycle"], args, stdout, stderr)`,
				`c := newClient(cfg); return lifecycleExport(c, args[1:], stdout, stderr)`,
			)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, []byte("\nfunc lifecycleExport(c int, args []string, stdout, stderr int) int "+tc.body+"\n")...)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewValidator(root)
			if err != nil {
				t.Fatal(err)
			}
			registry := fixtureRegistry()
			registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl lifecycle export"}}
			rejected := containsViolation(validator.Validate(registry), "F1", "cli", "invalid-ref")
			if rejected != tc.wantReject {
				t.Fatalf("rejected = %v, want %v", rejected, tc.wantReject)
			}
		})
	}
}

func TestNestedTopLevelDispatcherDecoyIsRejected(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "cli.go")
	body := `package cli
func RunWithStdin(args []string) int {
	rest := args
	_ = func() { switch rest[0] { case "test": return } }
	return 2
}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), "exact rest := fs.Args(), empty-command guard, switch tail is missing") {
		t.Fatalf("NewValidator error = %v, want nested dispatcher rejection", err)
	}
}

func TestUnreachableGenericDispatcherIsRejected(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "cli.go")
	writeFixtureMutation(t, path, `default: if spec`, `default: return 2; if spec`)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl bgp events"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want unreachable generic dispatcher rejection", violations)
	}
}

func TestTopLevelCommandSwitchTailMustBeExactAndReachable(t *testing.T) {
	for _, replacement := range []string{
		`return 2; switch rest[0]`,
		`rest[0] = "help"; switch rest[0]`,
		`if true { return 2 }; switch rest[0]`,
	} {
		root := fixtureRepo(t)
		path := filepath.Join(root, "internal", "cli", "cli.go")
		writeFixtureMutation(t, path, `switch rest[0]`, replacement)
		if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), "top-level dispatcher") {
			t.Fatalf("NewValidator error = %v, want exact reachable dispatcher-tail rejection", err)
		}
	}
}

func TestTopLevelCommandPreludeCannotTerminateBeforeExactTail(t *testing.T) {
	for _, prefix := range []string{
		`return 2; `,
		`if cfg.JSON { return 2 }; `,
	} {
		root := fixtureRepo(t)
		path := filepath.Join(root, "internal", "cli", "cli.go")
		writeFixtureMutation(t, path, `rest := fs.Args()`, prefix+`rest := fs.Args()`)
		if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), "top-level dispatcher") {
			t.Fatalf("NewValidator error = %v, want unreachable dispatcher-tail rejection", err)
		}
	}
}

func TestGenericDispatcherBodyMustBeExactDelegate(t *testing.T) {
	root := fixtureRepo(t)
	path := filepath.Join(root, "internal", "cli", "cli.go")
	writeFixtureMutation(t, path, `{ return cmdSurface(cfg, spec, rest[1:], stdout, stderr) }`, `{ return 2; return cmdSurface(cfg, spec, rest[1:], stdout, stderr) }`)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := fixtureRegistry()
	registry.Capabilities[0].CLI = Cell{Refs: []string{"cli:probectl bgp events"}}
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "cli", "invalid-ref") {
		t.Fatalf("violations = %#v; want non-exact generic delegate rejection", violations)
	}
}

func TestGenericCommandCalleeMustExecuteRawOperation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		old         string
		replacement string
		want        string
	}{
		{
			name:        "delegate deleted",
			old:         `return runRawOperation(cfg, op, args[1:], stdout, stderr)`,
			replacement: `return 2`,
			want:        "directly return runRawOperation",
		},
		{
			name:        "delegate unreachable",
			old:         `return runRawOperation(cfg, op, args[1:], stdout, stderr)`,
			replacement: `return 2; return runRawOperation(cfg, op, args[1:], stdout, stderr)`,
			want:        "directly return runRawOperation",
		},
		{
			name:        "request unreachable",
			old:         `if err := newClient(cfg).do(op.Method, path, body, &out);`,
			replacement: `return 2; if err := newClient(cfg).do(op.Method, path, body, &out);`,
			want:        "must execute the tenant-scoped HTTP client request",
		},
		{
			name:        "operation rewritten",
			old:         `var out any;`,
			replacement: `op = wrongOperation; var out any;`,
			want:        "must execute the tenant-scoped HTTP client request",
		},
		{
			name:        "path rewritten through pointer alias",
			old:         `var out any;`,
			replacement: `pathAlias := &path; *pathAlias = "/v1/wrong-operation"; var out any;`,
			want:        "must execute the tenant-scoped HTTP client request",
		},
		{
			name:        "path rewritten through call side effect",
			old:         `var out any;`,
			replacement: `fmt.Sscan("/v1/wrong-operation", &path); var out any;`,
			want:        "must execute the tenant-scoped HTTP client request",
		},
		{
			name:        "request arguments rewritten",
			old:         `newClient(cfg).do(op.Method, path, body, &out)`,
			replacement: `newClient(cfg).do(wrong.Method, "/v1/wrong", body, &out)`,
			want:        "must execute the tenant-scoped HTTP client request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "cli", "generic.go")
			writeFixtureMutation(t, path, tc.old, tc.replacement)
			if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewValidator error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSpecialCLIDispatchRequiresArgsTagAndExecutableCase(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{name: "wrong switch tag", old: `switch args[0]`, replacement: `switch "never"`},
		{name: "empty label", old: `return runRawOperation()`, replacement: `return 2`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "cli", "commands.go")
			writeFixtureMutation(t, path, tc.old, tc.replacement)
			validator, err := NewValidator(root)
			if tc.name == "wrong switch tag" {
				if err == nil || !strings.Contains(err.Error(), "switch on args[0]") {
					t.Fatalf("NewValidator error = %v, want wrong-tag rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			violations := validator.Validate(fixtureRegistry())
			if !containsViolation(violations, "F1", "cli", "invalid-ref") {
				t.Fatalf("violations = %#v; want empty special case rejection", violations)
			}
		})
	}
}

func TestSpecialCLIEntryAndCustomCalleeMustRemainReachable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		old         string
		replacement string
	}{
		{
			name:        "special switch unreachable",
			old:         `c := newClient(cfg); switch args[0]`,
			replacement: `c := newClient(cfg); return 2; switch args[0]`,
		},
		{
			name:        "test create request unreachable",
			old:         `func testCreate(cfg, c int, args []string, stdout, stderr int) int {`,
			replacement: `func testCreate(cfg, c int, args []string, stdout, stderr int) int { return 2;`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureRepo(t)
			path := filepath.Join(root, "internal", "cli", "commands.go")
			writeFixtureMutation(t, path, tc.old, tc.replacement)
			if _, err := NewValidator(root); err == nil || !strings.Contains(err.Error(), "CLI dispatcher") {
				t.Fatalf("NewValidator error = %v, want unreachable special CLI rejection", err)
			}
		})
	}
}

func mutateCLIAndAddDecoyComment(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(data), old, replacement, 1)
	if mutated == string(data) {
		t.Fatalf("mutation did not find %q", old)
	}
	mutated += "\n// decoy deleted dispatcher text: " + old + "\n"
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
}
