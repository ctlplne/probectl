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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

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
			!(strings.Contains(name, "isolation") && strings.HasSuffix(name, "_test.go")) {
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
