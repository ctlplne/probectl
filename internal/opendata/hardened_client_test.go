// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package opendata

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestOpenDataHTTPClientsHardened is a source ratchet: production open-data
// fetchers may accept an injected Doer, but their default must come from
// crypto.HardenedHTTPClient. Constructing net/http.Client (or using its global
// default) here would bypass the shared TLS floor and redirect policy.
func TestOpenDataHTTPClientsHardened(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(thisFile), "*.go"))
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue // injected test clients are deliberately unconstrained
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		httpAliases := map[string]bool{}
		for _, imp := range file.Imports {
			name := "http"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err == nil && importPath == "net/http" && name != "_" && name != "." {
				httpAliases[name] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.CompositeLit:
				if isHTTPSelector(n.Type, httpAliases, "Client") {
					t.Errorf("%s: bare net/http Client construction bypasses crypto.HardenedHTTPClient", fset.Position(n.Pos()))
				}
			case *ast.CallExpr:
				builtin, isIdent := n.Fun.(*ast.Ident)
				if isIdent && builtin.Name == "new" && len(n.Args) == 1 &&
					isHTTPSelector(n.Args[0], httpAliases, "Client") {
					t.Errorf("%s: new(net/http.Client) bypasses crypto.HardenedHTTPClient", fset.Position(n.Pos()))
				}
			case *ast.SelectorExpr:
				if isHTTPSelector(n, httpAliases, "DefaultClient") {
					t.Errorf("%s: net/http DefaultClient bypasses crypto.HardenedHTTPClient", fset.Position(n.Pos()))
				}
			}
			return true
		})
	}
}

func isHTTPSelector(expr ast.Expr, aliases map[string]bool, selector string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != selector {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && aliases[pkg.Name]
}
