// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

package pricing

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestCalculatorHasNoDirectNetworkDependency(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		filename := entry.Name()
		file, err := parser.ParseFile(files, filename, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			importSpec, ok := node.(*ast.ImportSpec)
			if !ok {
				return true
			}
			path, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", filename, err)
			}
			if path == "net" || strings.HasPrefix(path, "net/") {
				t.Errorf("offline calculator imports network package %q in %s", path, filename)
			}
			return true
		})
	}
}
