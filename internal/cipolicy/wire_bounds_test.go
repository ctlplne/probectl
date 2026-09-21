// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// The wire-bounds gate (Foundation-Loop S-9e6855ec). Decoders that consume
// untrusted network bytes read them through internal/wire — never by indexing
// or re-slicing the byte slice themselves. This makes the OLD WAY (hand-rolled
// offset arithmetic, unchecked fixed-offset slicing, a private per-protocol
// cursor) fail the build, so the sixth protocol cannot invent a sixth idiom.
//
// The rule, applied to every non-test file in the guarded decoder packages:
// a function that OWNS a raw datagram — it builds a wire.Reader from one of
// its own []byte parameters, the shape of every decoder entry point — may
// mention that parameter only to scope the reader (wire.New(pkt[:n])). Any
// other index or slice of it is the old idiom returning, and fails. Reading
// through the Reader produces no such expression at all, which is the point.
//
// Helpers that receive slices the Reader already carved and length-checked
// are deliberately out of scope; see byteSliceIndexing for why.
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

// wireGuardedPackages consume untrusted bytes off the network. internal/siem
// is deliberately absent: its syslog framing is bounded by bufio.Scanner and
// its parsers work on STRINGS with explicit index guards, a different shape
// this byte-slice rule would not describe (see the package's own tests).
var wireGuardedPackages = []string{
	"../flow",
	"../bgp",
}

// byteSliceIndexing reports hand-indexing of a RAW DATAGRAM inside the
// function that owns it.
//
// A function "owns a raw datagram" when it builds a wire.Reader from one of
// its own []byte parameters — that is the shape of every decoder entry point.
// Inside such a function the parameter may appear ONLY as the argument to
// wire.New (scoping the reader, e.g. wire.New(pkt[:headerLen])); every other
// index or slice of it is the old idiom returning, and fails.
//
// Downstream helpers are deliberately out of scope: they receive slices the
// reader already carved and length-checked (an IPFIX field value, an sFlow
// sampled header), where indexing after a len() switch is correct and the
// bounds question was already answered upstream. The rule targets exactly the
// place where raw network input meets offset arithmetic.
func byteSliceIndexing(fset *token.FileSet, file *ast.File) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Type.Params == nil {
			continue
		}
		params := map[string]bool{}
		for _, field := range fn.Type.Params.List {
			if !isByteSlice(field.Type) {
				continue
			}
			for _, name := range field.Names {
				params[name.Name] = true
			}
		}
		if len(params) == 0 {
			continue
		}
		// Which parameters does this function hand to wire.New? Those are the
		// raw datagrams it owns. Record the wire.New argument nodes so they
		// are not themselves reported.
		owned := map[string]bool{}
		sanctioned := map[ast.Node]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "New" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "wire" {
				return true
			}
			switch arg := call.Args[0].(type) {
			case *ast.Ident:
				if params[arg.Name] {
					owned[arg.Name] = true
				}
			case *ast.SliceExpr:
				if id, ok := arg.X.(*ast.Ident); ok && params[id.Name] {
					owned[id.Name] = true
					sanctioned[arg] = true
				}
			}
			return true
		})
		if len(owned) == 0 {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sanctioned[n] {
				return true
			}
			var operand ast.Expr
			switch e := n.(type) {
			case *ast.IndexExpr:
				operand = e.X
			case *ast.SliceExpr:
				operand = e.X
			default:
				return true
			}
			id, ok := operand.(*ast.Ident)
			if !ok || !owned[id.Name] {
				return true
			}
			pos := fset.Position(n.Pos())
			out = append(out, pos.Filename+":"+itoa(pos.Line)+" hand-indexes the raw datagram "+id.Name+
				" (read it through the wire.Reader built from it)")
			return true
		})
	}
	sort.Strings(out)
	return out
}

func isByteSlice(e ast.Expr) bool {
	arr, ok := e.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	id, ok := arr.Elt.(*ast.Ident)
	return ok && id.Name == "byte"
}

func TestWireBoundsDecodersReadThroughTheBoundedReader(t *testing.T) {
	var violations []string
	for _, pkg := range wireGuardedPackages {
		fset := token.NewFileSet()
		entries, err := os.ReadDir(pkg)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(pkg, name)
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatal(perr)
			}
			violations = append(violations, byteSliceIndexing(fset, f)...)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("decoders must read untrusted bytes through internal/wire, never by indexing them:\n%s",
			strings.Join(violations, "\n"))
	}
}

func TestWireBoundsSelfTestCatchesPlantedIndexing(t *testing.T) {
	fset := token.NewFileSet()
	planted, err := parser.ParseFile(fset, "planted.go", `package flow

import "github.com/ctlplne/probectl/internal/wire"

// The old way creeping back INTO an entry point that owns the datagram: a
// reader for some of it, hand-computed offsets for the rest. Both shapes the
// finding recorded (unchecked slice, unchecked index) must fail.
func decodeMixed(pkt []byte) uint32 {
	r := wire.New(pkt)
	_ = r.U16()
	hdr := pkt[0:4] // unchecked fixed-offset slice
	_ = pkt[7]      // unchecked index
	return uint32(hdr[0])
}

// Scoping the reader with a slice is the SANCTIONED move, not a violation.
func decodeBounded(pkt []byte) uint32 {
	r := wire.New(pkt[:8])
	return r.U32()
}

// A helper operating on a reader-carved, length-checked value is out of
// scope: the bounds question was answered upstream.
func readUint(b []byte) uint64 {
	if len(b) != 1 {
		return 0
	}
	return uint64(b[0])
}
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := byteSliceIndexing(fset, planted)
	if len(found) != 2 {
		t.Fatalf("planted hand-indexing: got %d findings, want 2:\n%s", len(found), strings.Join(found, "\n"))
	}
	for _, f := range found {
		if strings.Contains(f, "readUint") {
			t.Fatalf("false positive on a reader-carved value: %s", f)
		}
	}
}
