// SPDX-License-Identifier: LicenseRef-probectl-TBD

package apierror

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConstructorsSetKindAndCode(t *testing.T) {
	cases := []struct {
		e    *Error
		kind Kind
		code string
	}{
		{Internal("x"), KindInternal, "internal"},
		{BadRequest("x"), KindBadRequest, "bad_request"},
		{Validation("x"), KindValidation, "validation"},
		{Unauthorized("x"), KindUnauthorized, "unauthorized"},
		{Forbidden("x"), KindForbidden, "forbidden"},
		{NotFound("x"), KindNotFound, "not_found"},
		{Conflict("x"), KindConflict, "conflict"},
		{Unavailable("x"), KindUnavailable, "unavailable"},
		{RateLimited("x"), KindRateLimited, "rate_limited"},
		{TooLarge("x"), KindTooLarge, "too_large"},
	}
	for _, c := range cases {
		if c.e.Kind != c.kind {
			t.Errorf("%q: kind = %v, want %v", c.e.Code, c.e.Kind, c.kind)
		}
		if c.e.Code != c.code {
			t.Errorf("code = %q, want %q", c.e.Code, c.code)
		}
	}
}

func TestRegisteredCodesCoverConstructors(t *testing.T) {
	for _, e := range []*Error{
		Internal("x"),
		BadRequest("x"),
		Validation("x"),
		Unauthorized("x"),
		Forbidden("x"),
		NotFound("x"),
		Conflict("x"),
		Unavailable("x"),
		RateLimited("x"),
		TooLarge("x"),
	} {
		if !IsRegisteredCode(e.Code) {
			t.Errorf("constructor code %q is not in the public registry", e.Code)
		}
	}
}

func TestRegisteredCodesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, code := range RegisteredCodes() {
		if code == "" {
			t.Fatal("registered error code must not be empty")
		}
		if seen[code] {
			t.Fatalf("duplicate registered error code %q", code)
		}
		seen[code] = true
	}
}

func TestWithCodeStringLiteralsAreRegistered(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	dirs := []string{"cmd", "ee", "internal", "pkg"}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
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
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "WithCode" {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				code, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Errorf("%s: invalid WithCode literal %s", fset.Position(lit.Pos()), lit.Value)
					return true
				}
				if !IsRegisteredCode(code) {
					t.Errorf("%s: WithCode(%q) is not in the public registry", fset.Position(lit.Pos()), code)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestWrapUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	e := NotFound("missing").Wrap(cause)
	if !errors.Is(e, cause) {
		t.Error("errors.Is should find the wrapped cause")
	}
}

func TestAs(t *testing.T) {
	wrapped := fmt.Errorf("service: %w", Conflict("dup"))
	got, ok := As(wrapped)
	if !ok || got.Kind != KindConflict {
		t.Errorf("As(wrapped) = (%v, %v), want a KindConflict error", got, ok)
	}
	if _, ok := As(errors.New("plain")); ok {
		t.Error("As(plain error) should be false")
	}
}

func TestWithCode(t *testing.T) {
	e := Validation("bad").WithCode(string(CodeQuotaExceeded))
	if e.Code != string(CodeQuotaExceeded) {
		t.Errorf("Code = %q, want %s", e.Code, CodeQuotaExceeded)
	}
}

func TestLocalizedMessageUsesStableCode(t *testing.T) {
	e := NotFound("test not found")
	if got := e.LocalizedMessage("es-MX"); got != "No encontrado" {
		t.Fatalf("LocalizedMessage = %q, want No encontrado", got)
	}
	if got := LocalizedMessage("es", "custom_code", "custom detail"); got != "custom detail" {
		t.Fatalf("custom fallback = %q", got)
	}
}
