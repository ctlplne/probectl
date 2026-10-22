// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
)

// TestVerifyExportedEntryPoint exercises the agent-facing Verify (PLAT-13): the
// exported verification contract the agent's pull loop uses must accept a
// correctly-signed, newer bundle and refuse a tampered one.
func TestVerifyExportedEntryPoint(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(Bundle{TenantID: "t-a", Epoch: 100, Tests: []Test{
		{ID: "x", Type: "icmp", Target: "10.0.0.1", IntervalSeconds: 30, TimeoutSeconds: 5},
	}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, pub, 50); err != nil {
		t.Fatalf("Verify rejected a valid newer bundle: %v", err)
	}
	tampered := append([]byte(nil), signed...)
	for i := range tampered {
		if tampered[i] == 'x' {
			tampered[i] = 'y'
			break
		}
	}
	if _, err := Verify(tampered, pub, 50); err == nil {
		t.Fatal("Verify accepted a tampered bundle")
	}
}

// TestAgentVerifiesBundleBeforeApplying replaces the ING-20 "pull loop not yet
// wired" guard now that it is wired (G9, D-41). The shipped agent must import
// this package, and in its bundle-acceptance path the signature check
// (testsync.Verify) and the certificate-tenant check must both come BEFORE the
// first call that changes what the host runs (applyCentral). Reordering them,
// or dropping either check, fails here; the behavioral proofs live in
// internal/agent/testsync_test.go (tampered, foreign-tenant, replayed bundles
// never reach the host).
func TestAgentVerifiesBundleBeforeApplying(t *testing.T) {
	const src = "../../internal/agent/testsync.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	imported := false
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "github.com/ctlplne/probectl/internal/testsync" {
			imported = true
		}
	}
	if !imported {
		t.Fatal("the agent no longer imports internal/testsync: central test bundles are not verified")
	}
	var accept *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "accept" && fn.Recv != nil {
			accept = fn
		}
	}
	if accept == nil {
		t.Fatal("internal/agent/testsync.go has no accept method: the bundle-acceptance path moved; update this guard")
	}
	verifyAt, tenantAt, applyAt := token.NoPos, token.NoPos, token.NoPos
	ast.Inspect(accept.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testsync" && sel.Sel.Name == "Verify" && verifyAt == token.NoPos {
					verifyAt = x.Pos()
				}
				if sel.Sel.Name == "applyCentral" && applyAt == token.NoPos {
					applyAt = x.Pos()
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.NEQ && tenantAt == token.NoPos {
				l, lok := x.X.(*ast.SelectorExpr)
				r, rok := x.Y.(*ast.SelectorExpr)
				if lok && rok && l.Sel.Name == "TenantID" && r.Sel.Name == "tenantID" {
					tenantAt = x.Pos()
				}
			}
		}
		return true
	})
	if verifyAt == token.NoPos || tenantAt == token.NoPos || applyAt == token.NoPos {
		t.Fatalf("accept must call testsync.Verify (%v), compare the bundle TenantID with the certificate tenantID (%v), "+
			"and apply via applyCentral (%v)", verifyAt.IsValid(), tenantAt.IsValid(), applyAt.IsValid())
	}
	if verifyAt >= applyAt || tenantAt >= applyAt {
		t.Fatalf("accept applies the bundle before verifying it: Verify at %s, tenant check at %s, apply at %s",
			fset.Position(verifyAt), fset.Position(tenantAt), fset.Position(applyAt))
	}
}
