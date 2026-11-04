// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"go/ast"
	"go/parser"
	"go/token"
)

// A custom import request is reachable only while its input reader and entire
// byte ceiling remain exact. A helper name alone cannot confer gate coverage.
func (v *Validator) dashboardManifestReaderIsBounded(functions map[string][]*ast.FuncDecl) bool {
	readers := functions["readDashboardManifest"]
	if len(readers) != 1 || !cliBodyMatches(readers[0].Body, dashboardManifestReaderSpine) {
		return false
	}
	path, err := v.resolveWithinRoot("internal/cli/commands.go")
	if err != nil {
		return false
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return false
	}
	found := 0
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range value.Names {
				if name.Name != "maxDashboardManifestInput" {
					continue
				}
				found++
				if len(value.Names) != 1 || len(value.Values) != 1 {
					return false
				}
				shift, ok := value.Values[0].(*ast.BinaryExpr)
				if !ok || shift.Op != token.SHL {
					return false
				}
				left, leftOK := cliIntegerLiteral(shift.X)
				right, rightOK := cliIntegerLiteral(shift.Y)
				if !leftOK || !rightOK || left != 64 || right != 10 {
					return false
				}
			}
		}
	}
	return found == 1
}

const dashboardManifestReaderSpine = `{
	reader := stdin
	var closeFile func() error
	if filename != "-" {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("open %q: %w", filename, err)
		}
		reader = file
		closeFile = file.Close
	}
	if closeFile != nil {
		defer closeFile()
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxDashboardManifestInput+1))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if len(data) > maxDashboardManifestInput {
		return nil, fmt.Errorf("manifest exceeds %d-byte limit", maxDashboardManifestInput)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || !json.Valid(data) {
		return nil, fmt.Errorf("manifest must be one valid JSON object")
	}
	return data, nil
}`
