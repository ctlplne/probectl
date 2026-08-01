// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package testsupport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestClickHouseIsolationMandatoryServicePolicy(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve policy test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	// S-208ed3d9: DISCOVER every isolation- or integration-tagged test file
	// instead of naming seven. The previous list left two isolation files
	// outside the guard entirely, and any new required suite joined them by
	// default — a cross-tenant isolation suite that quietly skips is vacuous
	// green, which is this guard's own stated reason for existing.
	targets, err := requiredSuiteFiles(root)
	if err != nil {
		t.Fatalf("discover required suites: %v", err)
	}
	if len(targets) < 20 {
		t.Fatalf("discovery found only %d required-suite files; the guard's reach collapsed", len(targets))
	}
	var violations []string
	for _, rel := range targets {
		path := filepath.Join(root, rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, line := range bareSkipLines(fset, file) {
			violations = append(violations, rel+":"+strconv.Itoa(line))
		}
	}
	if len(violations) != 0 {
		t.Fatalf(
			"ClickHouse isolation suites bypass PROBECTL_TEST_REQUIRE_SERVICES; use testsupport.SkipOrFatal: %s",
			strings.Join(violations, ", "),
		)
	}

	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	workflowText := string(workflow)
	jobStart := strings.Index(workflowText, "\n  cross-tenant-isolation:\n")
	jobEnd := strings.Index(workflowText, "\n  integration:\n")
	if jobStart < 0 || jobEnd <= jobStart {
		t.Fatal("cross-tenant-isolation CI job boundaries are missing")
	}
	isolationJob := workflowText[jobStart:jobEnd]
	for _, want := range []string{
		"PROBECTL_PATHSTORE_URL: http://default:probectl@localhost:8123",
		"PROBECTL_OTELSTORE_URL: http://default:probectl@localhost:8123",
		"PROBECTL_EBPFSTORE_URL: http://default:probectl@localhost:8123",
		`PROBECTL_TEST_REQUIRE_SERVICES: "1"`,
		"SQL_probectl_tenant=ci-isolation",
	} {
		if !strings.Contains(isolationJob, want) {
			t.Errorf("cross-tenant isolation CI is missing %q", want)
		}
	}
}

// requiredSuiteFiles returns every repo-relative _test.go path carrying an
// isolation or integration build tag — the suites CI runs with
// PROBECTL_TEST_REQUIRE_SERVICES=1, where a skip is indistinguishable from a
// pass.
func requiredSuiteFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "third_party":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if !hasRequiredSuiteTag(string(src)) {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

// hasRequiredSuiteTag reports whether the source carries a //go:build
// constraint naming the isolation or integration tag.
func hasRequiredSuiteTag(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//go:build") {
			if line != "" && !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "package") {
				return false // past the header
			}
			continue
		}
		constraint := strings.TrimPrefix(line, "//go:build")
		for _, tag := range strings.FieldsFunc(constraint, func(r rune) bool {
			return r == ' ' || r == '&' || r == '|' || r == '(' || r == ')' || r == '!'
		}) {
			if tag == "isolation" || tag == "integration" {
				return true
			}
		}
	}
	return false
}

// bareSkipLines reports every t.Skip/Skipf call in file that is NOT routed
// through the fail-closed helper — at ANY nesting depth, and regardless of
// whether a t.Fatal happens to follow it in the same block. The old guard
// looked only for the call and was satisfied by a skip nested inside an if
// whose else branch fataled: the skip still ran, which is the whole failure
// mode (skip-before-fatal).
func bareSkipLines(fset *token.FileSet, file *ast.File) []int {
	var lines []int
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Skip" && sel.Sel.Name != "Skipf" && sel.Sel.Name != "SkipNow") {
			return true
		}
		// testsupport.SkipOrFatal is the sanctioned door: it honors
		// PROBECTL_TEST_REQUIRE_SERVICES and fatals in CI.
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testsupport" {
			return true
		}
		lines = append(lines, fset.Position(call.Pos()).Line)
		return true
	})
	sort.Ints(lines)
	return lines
}

func TestFlowClickHouseIsolationReaderErrorsMustFail(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve policy test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	path := filepath.Join(root, "internal", "store", "flowstore", "query_scoping_isolation_test.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read flow isolation test: %v", err)
	}
	if !clickHouseReaderErrorsFail(source, "TestClickHouseSettingScopedReaderPolicy") {
		t.Fatal("flow isolation test must fail every nonempty reader error")
	}
}

func TestOtelClickHouseIsolationReaderErrorsMustFail(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve policy test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	path := filepath.Join(root, "internal", "store", "otelstore", "query_scoping_isolation_test.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OTel isolation test: %v", err)
	}
	if !clickHouseReaderErrorsFail(source, "TestOtelSettingScopedReaderPolicy") {
		t.Fatal("OTel isolation test must fail every nonempty reader error")
	}
}

func clickHouseReaderErrorsFail(source []byte, target string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), target+".go", source, 0)
	if err != nil {
		return false
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != target || fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			guard, ok := stmt.(*ast.IfStmt)
			if !ok || !isErrTextNonempty(guard.Cond) {
				continue
			}
			for _, guardedStmt := range guard.Body.List {
				exprStmt, ok := guardedStmt.(*ast.ExprStmt)
				if !ok {
					continue
				}
				call, ok := exprStmt.X.(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Fatal" && sel.Sel.Name != "Fatalf") {
					continue
				}
				receiver, ok := sel.X.(*ast.Ident)
				if ok && receiver.Name == "t" {
					return true
				}
			}
		}
	}
	return false
}

func isErrTextNonempty(expr ast.Expr) bool {
	condition, ok := expr.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ {
		return false
	}
	return isIdent(condition.X, "errText") && isEmptyString(condition.Y) ||
		isEmptyString(condition.X) && isIdent(condition.Y, "errText")
}

func isIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

func isEmptyString(expr ast.Expr) bool {
	literal, ok := expr.(*ast.BasicLit)
	return ok && literal.Kind == token.STRING && literal.Value == `""`
}

func TestClickHouseIsolationReaderErrorPolicyRejectsUnrelatedBranch(t *testing.T) {
	for _, target := range []string{
		"TestClickHouseSettingScopedReaderPolicy",
		"TestOtelSettingScopedReaderPolicy",
	} {
		source := []byte(`package fixture
func TestEarlierReader(t *testing.T) {
	if errText != "" {
		t.Fatalf("reader read failed: %s", errText)
	}
}
func ` + target + `(t *testing.T) {
	if errText != "" {
		if strings.Contains(errText, "etting") {
			t.Skip("missing prerequisite")
		}
	}
	if n != 0 {
		t.Fatal("unexpected rows")
	}
}`)
		if clickHouseReaderErrorsFail(source, target) {
			t.Errorf("%s policy was incorrectly satisfied by an unrelated earlier assertion", target)
		}
	}
}

func TestIntegrationPostgresAvailabilityUsesMandatoryServicePolicy(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve policy test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	var violations []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, "_integration_test.go") &&
			(!strings.Contains(name, "isolation") || !strings.HasSuffix(name, "_test.go")) {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Skip" && sel.Sel.Name != "Skipf") {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			reason, err := strconv.Unquote(literal.Value)
			if err != nil || !postgresAvailabilityReason(reason) {
				return true
			}
			pos := fset.Position(call.Pos())
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			violations = append(violations, rel+":"+strconv.Itoa(pos.Line))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan integration availability policy: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf(
			"direct PostgreSQL availability skips bypass PROBECTL_TEST_REQUIRE_SERVICES; use testsupport.SkipOrFatal: %s",
			strings.Join(violations, ", "),
		)
	}
}

func TestPostgresAvailabilityReason(t *testing.T) {
	for _, reason := range []string{
		"no database available: %v",
		"Postgres unavailable: %v",
		"required database unavailable",
	} {
		if !postgresAvailabilityReason(reason) {
			t.Errorf("required-service reason %q was not recognized", reason)
		}
	}
	for _, reason := range []string{
		"test database is a replica",
		"path trace unavailable",
		"full-stack load gate is explicit",
	} {
		if postgresAvailabilityReason(reason) {
			t.Errorf("non-availability reason %q was misclassified", reason)
		}
	}
}

func postgresAvailabilityReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	return strings.Contains(reason, "no database available") ||
		strings.Contains(reason, "database unavailable") ||
		strings.Contains(reason, "postgres unavailable")
}

// TestSkipPolicyGuardCatchesPlantedShapes is the guard's own anti-vacuous
// proof (S-208ed3d9). The previous negative test anticipated a bare skip but
// not the SKIP-BEFORE-FATAL combination — a skip nested inside a conditional
// whose other branch fatals. That shape satisfied a "does a Fatal appear?"
// reading of the file while still skipping the suite, which is the entire
// failure mode: a cross-tenant isolation suite that quietly skips is vacuous
// green.
func TestSkipPolicyGuardCatchesPlantedShapes(t *testing.T) {
	for name, tc := range map[string]struct {
		src       string
		wantLines int
	}{
		"bare skip": {
			src: `package x
import "testing"
func TestA(t *testing.T) {
	if cond {
		t.Skip("no service")
	}
	t.Fatal("unreachable")
}`,
			wantLines: 1,
		},
		"skip before fatal, nested": {
			src: `package x
import "testing"
func TestA(t *testing.T) {
	if outer {
		if inner {
			t.Skipf("no service: %v", err)
		} else {
			t.Fatal("required")
		}
	}
}`,
			wantLines: 1,
		},
		"SkipNow at depth": {
			src: `package x
import "testing"
func TestA(t *testing.T) {
	for range items {
		func() {
			t.SkipNow()
		}()
	}
}`,
			wantLines: 1,
		},
		"sanctioned prerequisite door": {
			src: `package x
import (
	"testing"
	"github.com/ctlplne/probectl/internal/testsupport"
)
func TestA(t *testing.T) {
	if cond {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
}`,
			wantLines: 0,
		},
		"sanctioned opt-in door": {
			src: `package x
import (
	"testing"
	"github.com/ctlplne/probectl/internal/testsupport"
)
func TestA(t *testing.T) {
	if cond {
		testsupport.SkipOptIn(t, "PROBECTL_RUN_FULLSTACK_LOAD", "load gate")
	}
}`,
			wantLines: 0,
		},
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "planted.go", tc.src, 0)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if got := bareSkipLines(fset, file); len(got) != tc.wantLines {
			t.Errorf("%s: guard found %d bare skips, want %d", name, len(got), tc.wantLines)
		}
	}
}

// TestSkipPolicyGuardDiscoversNewFiles proves the reach is DISCOVERY, not a
// list: a synthetic required-suite file is recognized by its build tag alone.
func TestSkipPolicyGuardDiscoversNewFiles(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		want bool
	}{
		"isolation tag":           {"//go:build isolation\n\npackage x\n", true},
		"integration tag":         {"//go:build integration\n\npackage x\n", true},
		"combined tag":            {"//go:build integration && !race\n\npackage x\n", true},
		"unrelated tag":           {"//go:build devauth\n\npackage x\n", false},
		"no tag":                  {"package x\n", false},
		"tag-shaped body mention": {"package x\n\n// isolation is discussed here\nvar s = \"integration\"\n", false},
	} {
		if got := hasRequiredSuiteTag(tc.src); got != tc.want {
			t.Errorf("%s: hasRequiredSuiteTag = %v, want %v", name, got, tc.want)
		}
	}
}
