// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Command probectl-domainerrors is the domain-error vocabulary gate
// (Foundation-Loop S-ef8e66dc).
//
// THE RULE, not a denylist: an exported method of a store type must not hand a
// handler an error the handler has to CLASSIFY. Two shapes break that:
//
//	bare      — the method returns errors.New(...) / fmt.Errorf(...) directly,
//	            carrying no Kind, so every handler re-decides the status code
//	            and two handlers reach different answers for the same failure;
//	unmapped  — the method branches on pgx.ErrNoRows (or sql.ErrNoRows) and
//	            RETURNS THE RAW DRIVER ERROR ONWARD, so "this row does not
//	            exist" arrives at the transport as an opaque 500.
//
// A no-rows branch that returns a nil error is NOT a violation: treating
// absence as a normal outcome is a deliberate contract here — Sessions
// .LookupByHash conflates unknown/absolute-expired/idle-expired precisely so
// the endpoint cannot be used as a session oracle. The rule is that the branch
// RESOLVES the condition — classify it, or decide it is not an error — never
// about spelling.
//
// The rule is stated over ALL exported store methods, so a method added
// tomorrow is covered without editing this file. Deliberate exceptions live in
// scripts/domain_errors_allowlist.txt with a written reason each; a stale entry
// fails the gate, so the allowlist cannot quietly outlive its reason.
//
// -selftest plants one of each violation shape through a parser overlay, plus a
// correctly-classified method that must NOT be flagged, and drives them through
// the same analysis the live gate runs.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// storeDir is the package the rule governs: probectl's datastore adapters, the
// layer every handler reads through.
const storeDir = "internal/store"

// violation is one exported store method returning an unclassified error.
type violation struct {
	key    string // file:Recv.Method
	pos    string // file:line
	shape  string // "bare" | "unmapped-no-rows"
	detail string
}

func main() {
	selftest := flag.Bool("selftest", false, "plant each violation shape through an overlay and verify the gate flags exactly those")
	allowlistPath := flag.String("allowlist", "scripts/domain_errors_allowlist.txt", "allowlist file (file:Recv.Method entries with reasons)")
	flag.Parse()

	if *selftest {
		os.Exit(runSelftest())
	}
	found, err := analyze(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "domainerrors:", err)
		os.Exit(2)
	}
	os.Exit(report(found, *allowlistPath))
}

// analyze parses every non-test file in the store package and returns the
// violations. overlay maps a path to source text, used only by -selftest.
func analyze(overlay map[string]string) ([]violation, error) {
	paths, err := filepath.Glob(filepath.Join(storeDir, "*.go"))
	if err != nil {
		return nil, err
	}
	for p := range overlay {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	fset := token.NewFileSet()
	var out []violation
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		var src any
		if text, ok := overlay[path]; ok {
			src = text
		}
		file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || !fn.Name.IsExported() {
				continue // the rule governs exported METHODS: the handler-facing surface
			}
			if !returnsError(fn) {
				continue
			}
			out = append(out, inspect(fset, path, fn)...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out, nil
}

// returnsError reports whether fn has an error in its result list.
func returnsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, r := range fn.Type.Results.List {
		if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
			return true
		}
	}
	return false
}

func inspect(fset *token.FileSet, path string, fn *ast.FuncDecl) []violation {
	key := path + ":" + receiverName(fn) + "." + fn.Name.Name
	var out []violation

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ReturnStmt:
			for _, res := range node.Results {
				if name, ok := bareErrorConstructor(res); ok {
					out = append(out, violation{
						key: key, pos: position(fset, node.Pos()), shape: "bare",
						detail: "returns " + name + " with no apierror.Kind — every handler must re-decide the status code",
					})
				}
			}
		case *ast.IfStmt:
			if !isNoRowsCheck(node.Cond) {
				return true
			}
			if raw, ok := branchReturnsRawError(node.Body); ok {
				out = append(out, violation{
					key: key, pos: position(fset, node.Pos()), shape: "unmapped-no-rows",
					detail: "a no-rows branch returns the raw driver error " + raw + " — \"row does not exist\" reaches the transport as an opaque 500; classify it, or decide absence is not an error",
				})
			}
		}
		return true
	})
	return out
}

// bareErrorConstructor reports whether expr constructs an unclassified error.
func bareErrorConstructor(expr ast.Expr) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	switch {
	case pkg.Name == "errors" && sel.Sel.Name == "New",
		pkg.Name == "fmt" && sel.Sel.Name == "Errorf":
		return pkg.Name + "." + sel.Sel.Name, true
	}
	return "", false
}

// isNoRowsCheck matches a POSITIVE `errors.Is(x, pgx.ErrNoRows)` /
// `sql.ErrNoRows` test. A negated condition (`err != nil && !errors.Is(err,
// pgx.ErrNoRows)`) is the opposite statement — "no-rows is fine, keep going" —
// and its branch is about OTHER errors, so it is not this rule's business.
func isNoRowsCheck(cond ast.Expr) bool {
	negated := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.NOT {
			negated = true
			return false
		}
		return true
	})
	if negated {
		return false
	}
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ErrNoRows" {
			return true
		}
		found = true
		return false
	})
	return found
}

// branchReturnsRawError reports whether the branch hands an error VALUE straight
// back out — the raw driver error, unclassified. Returning a nil error (absence
// is not an error), a declared sentinel, or the result of a call
// (apierror.NotFound, or a store helper such as notFound/mapWriteErr that
// classifies) all resolve the condition and are not violations. A bare
// errors.New/fmt.Errorf inside the branch is reported by the "bare" rule
// instead, so it is not double-counted here.
func branchReturnsRawError(body *ast.BlockStmt) (string, bool) {
	raw := ""
	ast.Inspect(body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, r := range ret.Results {
			id, ok := r.(*ast.Ident)
			if !ok || id.Name == "nil" {
				continue
			}
			// A declared sentinel (ErrInvalidToken and friends) classifies BY
			// NAME: the handler switches on a named value, not on prose.
			if strings.HasPrefix(id.Name, "Err") {
				continue
			}
			if isErrorIdent(id) {
				raw = id.Name
			}
		}
		return true
	})
	return raw, raw != ""
}

// isErrorIdent is the conservative test for "this identifier holds the error
// being inspected": the conventional names. Widening it would flag ordinary
// value returns; narrowing it would miss the shape the rule exists for.
func isErrorIdent(id *ast.Ident) bool {
	switch id.Name {
	case "err", "e", "queryErr", "scanErr", "rowErr":
		return true
	}
	return false
}

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

func position(fset *token.FileSet, p token.Pos) string {
	pos := fset.Position(p)
	return fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
}

// report prints unallowed violations and stale allowlist entries.
func report(found []violation, allowlistPath string) int {
	allowed, err := readAllowlist(allowlistPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "domainerrors:", err)
		return 2
	}
	used := map[string]bool{}
	var unallowed []violation
	for _, v := range found {
		if _, ok := allowed[v.key]; ok {
			used[v.key] = true
			continue
		}
		unallowed = append(unallowed, v)
	}

	status := 0
	if len(unallowed) > 0 {
		fmt.Fprintf(os.Stderr, "domainerrors: %d exported store method(s) return an error a handler must classify:\n", len(unallowed))
		for _, v := range unallowed {
			fmt.Fprintf(os.Stderr, "  %s [%s]\n      %s\n", v.pos, v.shape, v.detail)
		}
		fmt.Fprintln(os.Stderr, "return an apierror (Kind + Code) so handlers MAP rather than invent,")
		fmt.Fprintln(os.Stderr, "or allowlist it WITH A REASON in "+allowlistPath)
		status = 1
	}
	var stale []string
	for key := range allowed {
		if !used[key] {
			stale = append(stale, key)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		fmt.Fprintf(os.Stderr, "domainerrors: %d stale allowlist entr(ies) — the violation is gone, delete the exemption:\n", len(stale))
		for _, k := range stale {
			fmt.Fprintln(os.Stderr, "  "+k)
		}
		status = 1
	}
	if status == 0 {
		fmt.Println("domainerrors: OK (every exported store method returns a classified error or a reasoned exemption)")
	}
	return status
}

// readAllowlist parses "file:Recv.Method — reason" lines. An entry without a
// reason is rejected: an exemption nobody had to justify is a denylist entry.
func readAllowlist(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, reason, ok := strings.Cut(text, "—")
		if !ok {
			key, reason, ok = strings.Cut(text, " -- ")
		}
		if !ok || strings.TrimSpace(reason) == "" {
			return nil, fmt.Errorf("%s:%d: allowlist entry needs a reason after an em dash: %q", path, line, text)
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(reason)
	}
	return out, sc.Err()
}

// runSelftest plants each violation shape and one correct method, then asserts
// the analysis flags exactly the violations. A gate that cannot fail is not a
// gate.
func runSelftest() int {
	const planted = storeDir + "/zz_domainerrors_planted.go"
	overlay := map[string]string{
		planted: `package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
)

type PlantedStore struct{}

// PlantedBare must be flagged: no Kind, so every handler re-decides.
func (PlantedStore) PlantedBare() error { return errors.New("planted: something went wrong") }

// PlantedBareWrapped must be flagged for the same reason.
func (PlantedStore) PlantedBareWrapped(err error) error {
	return fmt.Errorf("planted: wrapped: %w", err)
}

// PlantedUnmapped must be flagged: a no-rows branch that hands the raw driver
// error to the transport.
func (PlantedStore) PlantedUnmapped(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// PlantedClassified must NOT be flagged.
func (PlantedStore) PlantedClassified(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apierror.NotFound("planted not found")
	}
	return nil
}

// PlantedAbsenceIsNotAnError must NOT be flagged: deciding that a missing row
// is a normal outcome resolves the condition just as classifying it does.
func (PlantedStore) PlantedAbsenceIsNotAnError(err error) (bool, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return true, err
}

// PlantedNegatedNoRows must NOT be flagged: the branch is about OTHER errors.
func (PlantedStore) PlantedNegatedNoRows(err error) error {
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

// plantedUnexported must NOT be flagged: the rule governs the exported,
// handler-facing surface.
func (PlantedStore) plantedUnexported() error { return errors.New("planted: internal") }
`,
	}
	found, err := analyze(overlay)
	if err != nil {
		fmt.Fprintln(os.Stderr, "domainerrors selftest:", err)
		return 2
	}

	want := map[string]string{
		"PlantedBare":        "bare",
		"PlantedBareWrapped": "bare",
		"PlantedUnmapped":    "unmapped-no-rows",
	}
	mustNot := []string{"PlantedClassified", "plantedUnexported", "PlantedAbsenceIsNotAnError", "PlantedNegatedNoRows"}

	got := map[string]string{}
	for _, v := range found {
		if !strings.Contains(v.key, "zz_domainerrors_planted.go") {
			continue
		}
		name := v.key[strings.LastIndexByte(v.key, '.')+1:]
		got[name] = v.shape
	}
	status := 0
	for name, shape := range want {
		if got[name] != shape {
			fmt.Fprintf(os.Stderr, "domainerrors selftest: planted %s not flagged as %q (got %q) — the gate does not discriminate\n", name, shape, got[name])
			status = 1
		}
	}
	for _, name := range mustNot {
		if _, ok := got[name]; ok {
			fmt.Fprintf(os.Stderr, "domainerrors selftest: %s was flagged but is correct — the gate produces false positives\n", name)
			status = 1
		}
	}
	if status == 0 {
		fmt.Println("domainerrors SELFTEST: OK (bare + unmapped-no-rows planted and caught; classified and unexported methods left alone)")
	}
	return status
}
