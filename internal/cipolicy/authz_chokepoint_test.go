// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// The authz-chokepoint gate (Foundation-Loop S-6357f747). Authorization is one
// evaluator — auth.Decide, applied tenant-first, then RBAC, then ABAC deny —
// reached through exactly one door per surface (Server.decide for the control
// plane, the MCP dispatch, the provider wrappers). These tests make the OLD
// WAY — a surface reaching a resource with its own ad-hoc authorization
// sequence — fail the build:
//
//  1. mux registrations in internal/control may exist ONLY inside
//     (*Server).routes: a route wired anywhere else skips the permission table.
//  2. the evaluation primitives (auth.Decide/Authorize/Permit/Evaluate) may be
//     CALLED only from the declared chokepoint files; a new call site is a new
//     parallel authorization path.
//  3. every MCP tool literal declares a Permission.
//  4. every provider route is wrapped (asOperator/asTenantAdmin) or is listed
//     in providerPublicAuthPatterns with a reason, in exact correspondence.
//
// Every rule self-tests against planted violations driven through the SAME
// analysis functions the live checks use.
package cipolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---- analysis functions (pure; shared by live checks and self-tests) -------

// muxRegistrationsOutside reports mux.Handle/HandleFunc calls that occur
// outside the named function.
func muxRegistrationsOutside(fset *token.FileSet, file *ast.File, allowedFunc string) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Name != "mux" {
				return true
			}
			if name != allowedFunc {
				pos := fset.Position(call.Pos())
				out = append(out, pos.Filename+":"+itoa(pos.Line)+" mux registration in func "+name)
			}
			return true
		})
	}
	return out
}

// evaluatorCalls reports call sites of the authorization evaluation
// primitives (auth.Decide / Authorize / Permit / Evaluate).
func evaluatorCalls(fset *token.FileSet, file *ast.File) []string {
	primitives := map[string]bool{"Decide": true, "Authorize": true, "Permit": true, "Evaluate": true}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !primitives[sel.Sel.Name] {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "auth" {
			return true
		}
		pos := fset.Position(call.Pos())
		out = append(out, pos.Filename+":"+itoa(pos.Line)+" calls auth."+sel.Sel.Name)
		return true
	})
	return out
}

// mcpToolsMissingPermission reports Tool composite literals that carry a Name
// but no non-empty Permission.
func mcpToolsMissingPermission(fset *token.FileSet, file *ast.File) []string {
	var out []string
	// Track []Tool array literals so their element literals (which carry no
	// explicit type) are recognized as Tools — the real catalog is built that
	// way, and missing this shape made the first draft of this check vacuous.
	toolElems := map[*ast.CompositeLit]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if arr, ok := lit.Type.(*ast.ArrayType); ok && typeNamed(arr.Elt, "Tool") {
			for _, elt := range lit.Elts {
				if inner, ok := elt.(*ast.CompositeLit); ok {
					toolElems[inner] = true
				}
			}
		}
		isTool := toolElems[lit] || typeNamed(lit.Type, "Tool")
		hasName, hasPermission := false, false
		emptyPermission := false
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Name":
				hasName = true
			case "Permission":
				hasPermission = true
				if bl, ok := kv.Value.(*ast.BasicLit); ok && (bl.Value == `""` || bl.Value == "``") {
					emptyPermission = true
				}
			}
		}
		if isTool && hasName && (!hasPermission || emptyPermission) {
			pos := fset.Position(lit.Pos())
			out = append(out, pos.Filename+":"+itoa(pos.Line)+" MCP tool literal without a Permission declaration")
		}
		return true
	})
	return out
}

// providerHandleAudit returns (unwrappedPatterns, declaredPublicPatterns):
// h.handle calls whose handler argument is NOT h.asOperator(...) or
// h.asTenantAdmin(...) — including h.public registrations, which are the ONLY
// sanctioned unwrapped form and must match providerPublicAuthPatterns — and
// the patterns that map declares.
func providerHandleAudit(file *ast.File) (unwrapped, declaredPublic []string) {
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
				(sel.Sel.Name == "handle" || sel.Sel.Name == "public") && len(call.Args) == 2 {
				pattern := stringLit(call.Args[0])
				if pattern == "" {
					return true
				}
				if inner, ok := call.Args[1].(*ast.CallExpr); ok {
					if isel, ok := inner.Fun.(*ast.SelectorExpr); ok &&
						(isel.Sel.Name == "asOperator" || isel.Sel.Name == "asTenantAdmin") {
						return true // wrapped ✓
					}
				}
				unwrapped = append(unwrapped, pattern)
			}
		}
		if vs, ok := n.(*ast.ValueSpec); ok {
			for i, name := range vs.Names {
				if name.Name != "providerPublicAuthPatterns" || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.CompositeLit); ok {
					for _, elt := range lit.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if p := stringLit(kv.Key); p != "" {
								declaredPublic = append(declaredPublic, p)
							}
						}
					}
				}
			}
		}
		return true
	})
	sort.Strings(unwrapped)
	sort.Strings(declaredPublic)
	return unwrapped, declaredPublic
}

func typeNamed(e ast.Expr, name string) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == name
	case *ast.SelectorExpr:
		return t.Sel.Name == name
	}
	return false
}

func stringLit(e ast.Expr) string {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING || len(bl.Value) < 2 {
		return ""
	}
	return bl.Value[1 : len(bl.Value)-1]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func parseTree(t *testing.T, root string, skipTests bool) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if skipTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		files[path] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	treeFsets[root] = fset
	return files
}

var treeFsets = map[string]*token.FileSet{}

func parseSrc(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fset, f
}

// ---- live checks ------------------------------------------------------------

func TestAuthzChokepointRESTRegistration(t *testing.T) {
	files := parseTree(t, "../control", true)
	fset := treeFsets["../control"]
	var violations []string
	for _, f := range files {
		violations = append(violations, muxRegistrationsOutside(fset, f, "routes")...)
	}
	if len(violations) > 0 {
		t.Fatalf("mux registrations outside (*Server).routes — these skip the permission table:\n%s",
			strings.Join(violations, "\n"))
	}
}

// evaluatorChokepointFiles are the ONLY files (path-suffix keyed) that may
// call the auth evaluation primitives. Each entry states why it is a door:
// every one loads policies FAIL CLOSED and applies the single evaluator.
var evaluatorChokepointFiles = map[string]string{
	"control/abac.go":        "Server.decide — the control plane's single door (route chain + all in-handler re-authorizations)",
	"ai/mcp/server.go":       "the MCP dispatch routes every tool call through auth.Authorize after a fail-closed policy load",
	"control/ai.go":          "the AI composite path's per-source authorizer: fail-closed policy load + auth.Authorize immediately before each source dispatch",
	"ee/provider/handler.go": "the provider consent leg authenticates the TENANT session and decides via auth.Authorize with policies from AuthorizationContext (fail-closed load)",
}

func TestAuthzChokepointEvaluatorExile(t *testing.T) {
	var violations []string
	for _, root := range []string{"../control", "../ai", "../../ee"} {
		files := parseTree(t, root, true)
		fset := treeFsets[root]
		for path, f := range files {
			exempt := false
			norm := filepath.ToSlash(path)
			for suffix := range evaluatorChokepointFiles {
				if strings.HasSuffix(norm, suffix) {
					exempt = true
					break
				}
			}
			if exempt {
				continue
			}
			violations = append(violations, evaluatorCalls(fset, f)...)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("authorization primitives called outside the declared chokepoints (a parallel authorization path):\n%s\nroute the decision through Server.decide / the MCP dispatch instead",
			strings.Join(violations, "\n"))
	}
}

func TestAuthzChokepointMCPDeclarations(t *testing.T) {
	files := parseTree(t, "../ai/mcp", true)
	fset := treeFsets["../ai/mcp"]
	var violations []string
	for _, f := range files {
		violations = append(violations, mcpToolsMissingPermission(fset, f)...)
	}
	if len(violations) > 0 {
		t.Fatalf("MCP tools without a Permission declaration:\n%s", strings.Join(violations, "\n"))
	}
}

func TestAuthzChokepointProviderDeclarations(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../../ee/provider/handler.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, declared := providerHandleAudit(f)
	if strings.Join(unwrapped, "\n") != strings.Join(declared, "\n") {
		t.Fatalf("provider routes without an authorization wrapper must exactly match providerPublicAuthPatterns.\nunwrapped registrations:\n  %s\ndeclared public:\n  %s",
			strings.Join(unwrapped, "\n  "), strings.Join(declared, "\n  "))
	}
}

// ---- self-tests: plant each violation through the same analysis -------------

func TestAuthzChokepointSelfTestCatchesPlantedViolations(t *testing.T) {
	// 1. A mux registration outside routes().
	fset, f := parseSrc(t, `package control
func (s *Server) routes() { mux.Handle("GET /v1/ok", nil) }
func (s *Server) sneaky() { mux.Handle("GET /v1/leak", nil) }
`)
	if v := muxRegistrationsOutside(fset, f, "routes"); len(v) != 1 || !strings.Contains(v[0], "sneaky") {
		t.Fatalf("planted out-of-table mux registration not caught: %v", v)
	}

	// 2. A stray evaluator call.
	fset, f = parseSrc(t, `package x
func leak() { _ = auth.Evaluate(nil, "p", nil, nil) }
func fine() { helper.Evaluate() }
`)
	if v := evaluatorCalls(fset, f); len(v) != 1 || !strings.Contains(v[0], "auth.Evaluate") {
		t.Fatalf("planted evaluator call not caught (or false positive): %v", v)
	}

	// 3. An MCP tool without (and with empty) Permission; a declared one passes.
	fset, f = parseSrc(t, `package mcp
var tools = []Tool{
	{Name: "undeclared", Invoke: nil},
	{Name: "empty", Permission: ""},
	{Name: "declared", Permission: permTestRead},
}
`)
	if v := mcpToolsMissingPermission(fset, f); len(v) != 2 {
		t.Fatalf("planted undeclared MCP tools: got %d findings (%v), want 2", len(v), v)
	}

	// 4. An unwrapped provider route not in the declared public set.
	_, f = parseSrc(t, `package provider
func New() {
	h.public("POST /provider/v1/auth/login", h.handleLogin)
	h.handle("GET /provider/v1/leak", h.handleLeak)
	h.handle("GET /provider/v1/ok", h.asOperator("", h.handleOK))
}
var providerPublicAuthPatterns = map[string]string{
	"POST /provider/v1/auth/login": "session establishment",
}
`)
	unwrapped, declared := providerHandleAudit(f)
	if strings.Join(unwrapped, ",") == strings.Join(declared, ",") {
		t.Fatal("planted unwrapped provider route was not detected as a mismatch")
	}
	if len(unwrapped) != 2 || len(declared) != 1 {
		t.Fatalf("provider audit = unwrapped %v declared %v", unwrapped, declared)
	}
}
