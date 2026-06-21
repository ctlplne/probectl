// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cipolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	maxProductionFuncLines      = 250
	maxProductionDecisionTokens = 50
)

var productionComplexityAllowlist = map[string]string{
	"internal/govern/redact.go:columnCategory": "data-table switch: compact column-name classification table for redaction categories",
}

func TestProductionFunctionComplexityBudget(t *testing.T) {
	root := repoRoot(t)
	seenAllowlist := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if generatedGoFile(rel, path) {
			return nil
		}
		checkGoFileComplexity(t, rel, path, seenAllowlist)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for key, reason := range productionComplexityAllowlist {
		if strings.TrimSpace(reason) == "" {
			t.Fatalf("complexity allowlist entry %s has no reason", key)
		}
		if !seenAllowlist[key] {
			t.Fatalf("complexity allowlist entry %s no longer matches a measured production function; remove the stale exception", key)
		}
	}
}

func generatedGoFile(rel, path string) bool {
	if strings.HasSuffix(rel, ".pb.go") || strings.Contains(rel, ".gen.") || strings.Contains(rel, "_generated.") {
		return true
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if len(b) > 2048 {
		b = b[:2048]
	}
	return strings.Contains(string(b), "Code generated")
}

func checkGoFileComplexity(t *testing.T, rel, path string, seenAllowlist map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Pos()).Line
		end := fset.Position(fn.End()).Line
		lines := end - start + 1
		decisions := decisionTokens(fn.Body)
		key := rel + ":" + fn.Name.Name
		if _, ok := productionComplexityAllowlist[key]; ok {
			seenAllowlist[key] = true
			continue
		}
		if lines > maxProductionFuncLines || decisions > maxProductionDecisionTokens {
			t.Errorf("%s:%d %s is too complex: %d lines / %d decision tokens (budget %d / %d)",
				rel, start, fn.Name.Name, lines, decisions, maxProductionFuncLines, maxProductionDecisionTokens)
		}
	}
}

func decisionTokens(n ast.Node) int {
	count := 0
	ast.Inspect(n, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.CaseClause, *ast.CommClause, *ast.GoStmt, *ast.DeferStmt:
			count++
		case *ast.BinaryExpr:
			if x.Op == token.LAND || x.Op == token.LOR {
				count++
			}
		}
		return true
	})
	return count
}
