// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuarantineRegistryEnterCheckRelease(t *testing.T) {
	q := NewQuarantine()
	if err := q.Check("T-A"); err != nil {
		t.Fatalf("empty registry refused a tenant: %v", err)
	}
	stored, fresh := q.Enter(QuarantineEntry{TenantID: "T-A", Reason: QuarantinePlaneUnreachable, Plane: "eu",
		Detail: "dial tcp: lookup https://reader:hunter2@ch-eu.internal:8443/: no such host\nsecond line", Remedy: "restore it"})
	if !fresh || stored.TenantID != "t-a" || stored.Since.IsZero() {
		t.Fatalf("first Enter = %+v fresh=%v, want a new lower-cased entry with Since stamped", stored, fresh)
	}
	if strings.Contains(stored.Detail, "hunter2") || strings.Contains(stored.Detail, "second line") {
		t.Fatalf("detail kept credentials or later lines: %q", stored.Detail)
	}
	err := q.Check("t-A")
	var qe *QuarantinedError
	if !errors.Is(err, ErrTenantQuarantined) || !errors.As(err, &qe) || qe.Entry.Reason != QuarantinePlaneUnreachable {
		t.Fatalf("Check = %v, want the quarantined error (case-insensitive id)", err)
	}
	if err := q.Check("t-b"); err != nil {
		t.Fatalf("another tenant was refused: %v", err)
	}
	// A refreshed cause keeps the original Since and is not a new transition.
	time.Sleep(time.Millisecond)
	again, fresh := q.Enter(QuarantineEntry{TenantID: "t-a", Reason: QuarantineReaderScopeUnproven, Plane: "eu"})
	if fresh || !again.Since.Equal(stored.Since) || again.Reason != QuarantineReaderScopeUnproven {
		t.Fatalf("refresh = %+v fresh=%v, want the cause updated and Since kept", again, fresh)
	}
	counts := q.CountByReason()
	if len(counts) != len(QuarantineReasons()) || counts[QuarantineReaderScopeUnproven] != 1 || counts[QuarantinePlaneUnreachable] != 0 {
		t.Fatalf("CountByReason = %v", counts)
	}
	if _, ok := q.Release("T-A"); !ok {
		t.Fatal("Release did not find the tenant")
	}
	if err := q.Check("t-a"); err != nil {
		t.Fatalf("released tenant still refused: %v", err)
	}
	if entered, released := q.Transitions(); entered != 1 || released != 1 {
		t.Fatalf("transitions = %d/%d, want 1/1", entered, released)
	}
	var nilQ *Quarantine
	if nilQ.Check("x") != nil || nilQ.List() != nil {
		t.Fatal("a nil registry must be empty")
	}
}

// The tenant-facing message names the failed precondition and the plane and
// says who fixes it, but never carries the operator-side detail.
func TestQuarantineTenantMessageIsActionableAndCarriesNoDetail(t *testing.T) {
	for _, reason := range QuarantineReasons() {
		e := &QuarantinedError{Entry: QuarantineEntry{TenantID: "t-a", Reason: reason, Plane: "eu",
			Detail: "dial tcp 10.9.8.7:8443: connection refused", Remedy: "PROBECTL_DATAPLANES=eu=..."}}
		msg := e.TenantMessage()
		if strings.Contains(msg, "10.9.8.7") || strings.Contains(msg, "connection refused") {
			t.Errorf("%s: tenant message leaks the operator detail: %q", reason, msg)
		}
		if !strings.Contains(msg, "quarantined") || !strings.Contains(msg, "operator") || !strings.Contains(msg, "resumes automatically") {
			t.Errorf("%s: tenant message is not actionable: %q", reason, msg)
		}
		if reason != QuarantineSchemaCatchUpFailed && !strings.Contains(msg, `"eu"`) {
			t.Errorf("%s: tenant message does not name the plane: %q", reason, msg)
		}
		if full := e.Error(); !strings.Contains(full, "connection refused") || !strings.Contains(full, "fix:") {
			t.Errorf("%s: operator error lacks the detail and fix: %q", reason, full)
		}
	}
}

// InTenant refuses a quarantined tenant before it touches the pool; the
// quarantine notice is the one exemption.
func TestInTenantRefusesAQuarantinedTenantBeforeTheDatabase(t *testing.T) {
	prev := CurrentQuarantine()
	t.Cleanup(func() { SetQuarantine(prev) })
	q := NewQuarantine()
	SetQuarantine(q)
	q.Enter(QuarantineEntry{TenantID: "t-q", Reason: QuarantinePlaneMissing, Plane: "mars"})

	ctx := WithTenant(context.Background(), "t-q")
	called := false
	err := InTenant(ctx, nil, func(context.Context, Scope) error { called = true; return nil })
	if !errors.Is(err, ErrTenantQuarantined) || called {
		t.Fatalf("InTenant = %v (called=%v), want the quarantine refusal before any work", err, called)
	}
	err = InTenantProviderMaintenance(ctx, nil, func(context.Context, Scope) error { called = true; return nil })
	if !errors.Is(err, ErrTenantQuarantined) || called {
		t.Fatalf("InTenantProviderMaintenance = %v, want the quarantine refusal", err)
	}
	if err := pgQuarantineCheck(context.WithValue(ctx, quarantineNoticeKey{}, true), "t-q"); err != nil {
		t.Fatalf("the quarantine notice itself was refused: %v", err)
	}
	if err := pgQuarantineCheck(ctx, "t-other"); err != nil {
		t.Fatalf("an unquarantined tenant was refused: %v", err)
	}
}

// The quarantine notice is the only exemption from the refusal, so it has
// exactly one production caller: the supervisor's tenant-chain receipt.
func TestQuarantineNoticeHasOneCaller(t *testing.T) {
	root := filepath.Join("..", "..")
	var callers []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "web", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(src), "InTenantQuarantineNotice") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "InTenantQuarantineNotice" {
					callers = append(callers, filepath.ToSlash(path))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(callers) != 1 || !strings.HasSuffix(callers[0], "ee/silo/quarantine.go") {
		t.Fatalf("InTenantQuarantineNotice callers = %v, want exactly ee/silo/quarantine.go", callers)
	}
}
