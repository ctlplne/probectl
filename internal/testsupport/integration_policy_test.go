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
	targets := []string{
		"internal/store/endpointstore/isolation_clickhouse_integration_test.go",
		"internal/store/flowstore/isolation_clickhouse_test.go",
		"internal/store/flowstore/query_scoping_isolation_test.go",
		"internal/store/otelstore/query_scoping_isolation_test.go",
		"internal/store/ebpfstore/query_scoping_isolation_test.go",
		"internal/store/pathstore/isolation_clickhouse_test.go",
		"internal/store/pathstore/query_scoping_isolation_test.go",
	}
	var violations []string
	for _, rel := range targets {
		path := filepath.Join(root, rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Skip" && sel.Sel.Name != "Skipf") {
				return true
			}
			violations = append(
				violations,
				rel+":"+strconv.Itoa(fset.Position(call.Pos()).Line),
			)
			return true
		})
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
