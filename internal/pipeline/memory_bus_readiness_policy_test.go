// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMemoryBusReadinessDoesNotUseStartupSleeps(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve readiness policy test path")
	}
	pipelineDir := filepath.Dir(here)
	paths := []string{
		filepath.Join(pipelineDir, "flow_test.go"),
		filepath.Join(pipelineDir, "retry_dlq_test.go"),
		filepath.Join(pipelineDir, "..", "control", "resultview_test.go"),
		filepath.Join(pipelineDir, "..", "bgp", "bridge_test.go"),
	}

	for _, path := range paths {
		path := filepath.Clean(path)
		t.Run(filepath.Base(path), func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				decl, ok := node.(*ast.FuncDecl)
				if !ok || decl.Body == nil {
					return true
				}
				checkMemoryBusReadiness(t, fset, decl.Body)
				return false
			})
		})
	}
}

func checkMemoryBusReadiness(t *testing.T, fset *token.FileSet, body *ast.BlockStmt) {
	t.Helper()
	for index, stmt := range body.List {
		goStmt, ok := stmt.(*ast.GoStmt)
		if !ok || !readinessContainsSelectorCall(goStmt.Call, "Run", "Subscribe") {
			continue
		}

		for _, next := range body.List[index+1:] {
			if readinessContainsSelectorCall(next, "WaitForSubscribers") {
				break
			}
			if readinessContainsTimeSleep(next) {
				start := fset.Position(goStmt.Pos())
				sleep := fset.Position(next.Pos())
				t.Errorf(
					"%s:%d starts a memory-bus consumer, then %s:%d guesses readiness with time.Sleep; use a bounded WaitForSubscribers call",
					start.Filename,
					start.Line,
					sleep.Filename,
					sleep.Line,
				)
				break
			}
			if readinessContainsSelectorCall(next, "Publish") {
				start := fset.Position(goStmt.Pos())
				publish := fset.Position(next.Pos())
				t.Errorf(
					"%s:%d starts a memory-bus consumer, then publishes at %s:%d without WaitForSubscribers",
					start.Filename,
					start.Line,
					publish.Filename,
					publish.Line,
				)
				break
			}
		}
	}
}

func readinessContainsSelectorCall(node ast.Node, names ...string) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, name := range names {
			if selector.Sel.Name == name {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func readinessContainsTimeSleep(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Sleep" {
			return true
		}
		ident, ok := selector.X.(*ast.Ident)
		if ok && ident.Name == "time" {
			found = true
			return false
		}
		return true
	})
	return found
}
