// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// probectl-deadseams is the zero-call-site gate (Foundation-Loop T-2c9ab621):
// an exported symbol in internal/ or ee/ whose only references are its own
// definition and _test.go files is a seam that lies to the next reader — a
// capability a checklist will tick that no shipping path serves. This tool
// makes that shape fail the build.
//
// The rule (not a denylist): for every exported package-level func, type,
// const and var — plus methods, with interface-satisfaction awareness —
// declared in a non-test, non-generated file under internal/ or ee/, at least
// one reference must exist in a non-test file outside the symbol's own
// declaration. internal/ and ee/ cannot have importers outside this module,
// so the reference census is complete by construction.
//
// Deliberate exemptions carry a written reason in
// scripts/dead_seams_allowlist.txt; a stale allowlist entry (matching
// nothing) fails the gate so the list cannot rot into a denylist.
//
// SELFTEST plants both shapes through a compiler overlay — an inert exported
// symbol that must be flagged and a used one that must not be — so the gate
// proves it can fail before it is trusted.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const modulePath = "github.com/ctlplne/probectl"

// whySymbol, when set, prints the full census for one finding-format symbol.
var whySymbol string

// debugIface narrows why-iface prints to the whySymbol candidate's check.
var debugIface bool

// classifyMode emits machine-readable use classes instead of the gate report.
var classifyMode bool

// testUse records where a candidate's test-only references live.
type testUse struct{ samePkg, crossPkg int }

var testUses = map[objKey]*testUse{}

func main() {
	selftest := flag.Bool("selftest", false, "plant an inert and a used symbol via overlay; verify only the inert one is flagged")
	allowlistPath := flag.String("allowlist", "scripts/dead_seams_allowlist.txt", "allowlist file (symbol/package entries with reasons)")
	flag.StringVar(&whySymbol, "why", "", "diagnose one symbol: print its uses census and interface-exemption result")
	classify := flag.Bool("classify", false, "emit tab-separated use-class per inert symbol (none | tests-same-pkg | tests-cross-pkg)")
	flag.Parse()
	classifyMode = *classify

	if *selftest {
		os.Exit(runSelftest())
	}
	inert, err := analyzeAll(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deadseams:", err)
		os.Exit(2)
	}
	if classifyMode {
		for _, f := range inert {
			class := "none"
			for key, tu := range testUses {
				if keySymbol(key) == f.symbol {
					if tu.crossPkg > 0 {
						class = "tests-cross-pkg"
					} else if tu.samePkg > 0 {
						class = "tests-same-pkg"
					}
					break
				}
			}
			fmt.Printf("%s\t%s\t%s\n", class, f.symbol, f.pos)
		}
		os.Exit(0)
	}
	os.Exit(report(inert, *allowlistPath))
}

// keySymbol reconstructs the finding-format symbol from a key.
func keySymbol(k objKey) string {
	if k.recv != "" {
		return k.pkg + "." + k.recv + "." + k.name
	}
	return k.pkg + "." + k.name
}

// finding is one inert exported symbol.
type finding struct {
	symbol string // pkgpath.Name or pkgpath.Recv.Name
	pos    string // file:line
}

// objKey canonically identifies a package-level object across the plain and
// test-augmented package variants go/packages loads (whose types.Objects are
// distinct): module-path package, receiver type (for methods), and name.
type objKey struct {
	pkg  string
	recv string
	name string
}

// keyOf derives the canonical key, or ok=false for objects that cannot be
// package-level candidates (universe, method on unexported type, ...).
func keyOf(obj types.Object) (objKey, bool) {
	if obj == nil || obj.Pkg() == nil {
		return objKey{}, false
	}
	pkg := strings.TrimSuffix(obj.Pkg().Path(), "_test")
	pkg = strings.TrimSuffix(pkg, ".test")
	k := objKey{pkg: pkg, name: obj.Name()}
	if fn, ok := obj.(*types.Func); ok {
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			named := namedOf(sig.Recv().Type())
			if named == nil {
				return objKey{}, false
			}
			k.recv = named.Obj().Name()
		}
	}
	return k, true
}

func namedOf(t types.Type) *types.Named {
	for {
		switch tt := t.(type) {
		case *types.Pointer:
			t = tt.Elem()
		case *types.Named:
			return tt
		default:
			return nil
		}
	}
}

// analyzeAll runs the authoritative linux pass (the shipping agents and
// control plane; load errors are fatal) and then best-effort darwin and
// windows passes for the cross-platform CLI/endpoint builds: those GOOS
// cannot compile the whole tree, so they only contribute additional uses —
// a reference living in a platform-tagged file rescues its symbol, and a
// broken aux package can never flag one.
func analyzeAll(overlay map[string][]byte) ([]finding, error) {
	linux, err := analyze(overlay, "linux")
	if err != nil {
		return nil, fmt.Errorf("linux: %w", err)
	}
	rescued := map[string]bool{}
	for _, goos := range []string{"darwin", "windows"} {
		usedKeys, err := auxUsedKeys(overlay, goos)
		if err != nil {
			return nil, fmt.Errorf("%s aux pass: %w", goos, err)
		}
		for k := range usedKeys {
			rescued[keySymbol(k)] = true
		}
	}
	out := make([]finding, 0, len(linux))
	for _, f := range linux {
		if !rescued[f.symbol] {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].symbol < out[j].symbol })
	return out, nil
}

// auxUsedKeys loads one aux GOOS (tolerating per-package load errors) and
// returns every candidate-shaped key referenced from a non-test file there.
// Declaration-span exclusion is deliberately skipped: an aux pass may only
// mark symbols used (conservative in the safe direction).
func auxUsedKeys(overlay map[string][]byte, goos string) (map[objKey]bool, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Tests:   true,
		Overlay: overlay,
		Env:     append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0"),
	}
	pkgs, err := packages.Load(cfg, "./...", "./test/...")
	if err != nil {
		return nil, err
	}
	used := map[objKey]bool{}
	for _, pkg := range pkgs {
		for id, obj := range pkg.TypesInfo.Uses {
			key, ok := keyOf(origin(obj))
			if !ok || !guardedPackage(key.pkg) {
				continue
			}
			p := pkg.Fset.Position(id.Pos())
			if strings.HasSuffix(p.Filename, "_test.go") {
				continue
			}
			used[key] = true
		}
	}
	return used, nil
}

// analyze loads the module (tests included, plus overlay when non-nil) for one
// GOOS and returns every inert exported symbol under internal/ and ee/.
func analyze(overlay map[string][]byte, goos string) ([]finding, error) {
	// Default build tags (the ee-attached control plane), GOOS pinned by the
	// caller: platform-tagged files shape the reference graph.
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Tests:   true,
		Overlay: overlay,
		// Additive test tags so the -classify view (and use census) covers the
		// integration/isolation suites; they contain only _test.go files, so
		// the live-reference rule is unchanged by them.
		BuildFlags: []string{"-tags", "integration isolation"},
		Env:        append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0"),
	}
	// "./test/..." is a separate module, but Go's internal-visibility rule
	// keys on the import-path prefix, so it CAN consume internal/ — its
	// non-test files (e.g. the DR drill fixtures) are real references.
	pkgs, err := packages.Load(cfg, "./...", "./test/...")
	if err != nil {
		return nil, err
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("packages loaded with errors")
	}

	// Pass 1: candidate exported objects declared in internal/ or ee/
	// non-test, non-generated files, plus every interface method set seen
	// anywhere (for method exemption) and the declaration spans to exclude.
	// Candidates come from the PLAIN package variants only (go/packages also
	// loads test-augmented variants whose recompiled files duplicate every
	// object); the use census bridges variants through canonical objKeys.
	candidates := map[objKey]*finding{}
	candidateObj := map[objKey]types.Object{}
	declSpan := map[objKey][]span{}
	var interfaces []*types.Interface

	// The universe error interface lives in no package scope; without it every
	// Error() string method would look like a dead seam.
	if errType, ok := types.Universe.Lookup("error").Type().Underlying().(*types.Interface); ok {
		interfaces = append(interfaces, errType)
	}
	// errors.Unwrap/Is/As dispatch through ANONYMOUS interfaces declared
	// inline in the errors package — they appear in no scope, yet the methods
	// they call are load-bearing. Synthesize those shapes.
	errType := types.Universe.Lookup("error").Type()
	boolType := types.Typ[types.Bool]
	anyType := types.Universe.Lookup("any").Type()
	mk := func(name string, params, results []*types.Var) *types.Interface {
		sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(params...), types.NewTuple(results...), false)
		fn := types.NewFunc(token.NoPos, nil, name, sig)
		iface := types.NewInterfaceType([]*types.Func{fn}, nil)
		iface.Complete()
		return iface
	}
	v := func(t types.Type) *types.Var { return types.NewVar(token.NoPos, nil, "", t) }
	interfaces = append(interfaces,
		mk("Unwrap", nil, []*types.Var{v(errType)}),
		mk("Unwrap", nil, []*types.Var{v(types.NewSlice(errType))}),
		mk("Is", []*types.Var{v(errType)}, []*types.Var{v(boolType)}),
		mk("As", []*types.Var{v(anyType)}, []*types.Var{v(boolType)}),
	)

	seenPkg := map[*types.Package]bool{}
	var collectIfaces func(p *types.Package)
	collectIfaces = func(p *types.Package) {
		if p == nil || seenPkg[p] {
			return
		}
		seenPkg[p] = true
		for _, name := range p.Scope().Names() {
			if tn, ok := p.Scope().Lookup(name).(*types.TypeName); ok {
				if iface, ok := tn.Type().Underlying().(*types.Interface); ok {
					interfaces = append(interfaces, iface)
				}
			}
		}
		for _, imp := range p.Imports() {
			collectIfaces(imp)
		}
	}

	for _, pkg := range pkgs {
		collectIfaces(pkg.Types)
		if !guardedPackage(pkg.PkgPath) || pkg.ID != pkg.PkgPath {
			continue // test-augmented variant or out of scope
		}
		for _, file := range pkg.Syntax {
			pos := pkg.Fset.Position(file.Pos())
			if strings.HasSuffix(pos.Filename, "_test.go") || generated(file) {
				continue
			}
			for _, decl := range file.Decls {
				collectCandidates(pkg, decl, candidates, candidateObj, declSpan)
			}
		}
	}

	// Pass 2: census every use of a candidate, excluding its own declaration
	// span and (for types) receiver mentions in its own method declarations.
	// Uses resolve through canonical keys so a reference seen in either
	// package variant marks the one candidate.
	used := map[objKey]bool{}
	for _, pkg := range pkgs {
		for id, obj := range pkg.TypesInfo.Uses {
			key, ok := keyOf(origin(obj))
			if !ok {
				continue
			}
			if _, isCandidate := candidates[key]; !isCandidate {
				continue
			}
			p := pkg.Fset.Position(id.Pos())
			if whySymbol != "" && candidates[key].symbol == whySymbol {
				fmt.Printf("why: use at %s:%d test=%v inDeclSpan=%v (pkg variant %s)\n",
					relPath(p.Filename), p.Line, strings.HasSuffix(p.Filename, "_test.go"), inSpans(declSpan[key], p), pkg.ID)
			}
			if strings.HasSuffix(p.Filename, "_test.go") {
				if classifyMode {
					tu := testUses[key]
					if tu == nil {
						tu = &testUse{}
						testUses[key] = tu
					}
					usePkg := strings.TrimSuffix(strings.TrimSuffix(pkg.PkgPath, "_test"), ".test")
					if usePkg == key.pkg {
						tu.samePkg++
					} else {
						tu.crossPkg++
					}
				}
				continue
			}
			if inSpans(declSpan[key], p) {
				continue
			}
			used[key] = true
		}
	}

	var inert []finding
	for key, f := range candidates {
		if whySymbol != "" && f.symbol == whySymbol {
			fn, isFn := candidateObj[key].(*types.Func)
			debugIface = true
			fmt.Printf("why: %s candidate=true used=%v isFunc=%v ifaceExempt=%v (interfaces seen: %d)\n",
				f.symbol, used[key], isFn, isFn && implementsSomeInterface(fn, interfaces), len(interfaces))
			debugIface = false
		}
		if used[key] {
			continue
		}
		if fn, ok := candidateObj[key].(*types.Func); ok && implementsSomeInterface(fn, interfaces) {
			continue
		}
		inert = append(inert, *f)
	}
	sort.Slice(inert, func(i, j int) bool { return inert[i].symbol < inert[j].symbol })
	return inert, nil
}

type span struct {
	file       string
	start, end int // lines, inclusive
}

func inSpans(spans []span, p token.Position) bool {
	for _, s := range spans {
		if s.file == p.Filename && p.Line >= s.start && p.Line <= s.end {
			return true
		}
	}
	return false
}

// guardedPackage reports whether pkgPath is under internal/ or ee/ and not
// generated code. Test-binary package variants share the path of the package
// under test, so they are covered by the same prefix rules.
func guardedPackage(pkgPath string) bool {
	trimmed := strings.TrimSuffix(pkgPath, ".test")
	trimmed = strings.TrimSuffix(trimmed, "_test")
	if !strings.HasPrefix(trimmed, modulePath+"/internal/") && !strings.HasPrefix(trimmed, modulePath+"/ee/") {
		return false
	}
	if strings.Contains(trimmed, "/internal/gen/") {
		return false // generated protobuf/gNMI/prometheus surface
	}
	return true
}

func generated(file *ast.File) bool {
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if strings.Contains(c.Text, "Code generated") && strings.Contains(c.Text, "DO NOT EDIT") {
				return true
			}
		}
		if cg.End() > file.Package {
			break
		}
	}
	return false
}

func collectCandidates(pkg *packages.Package, decl ast.Decl, out map[objKey]*finding, objs map[objKey]types.Object, spans map[objKey][]span) {
	fset := pkg.Fset
	add := func(id *ast.Ident, declNode ast.Node, symbol string) {
		obj := pkg.TypesInfo.Defs[id]
		if obj == nil || !obj.Exported() {
			return
		}
		key, ok := keyOf(origin(obj))
		if !ok {
			return
		}
		p := fset.Position(id.Pos())
		start := fset.Position(declNode.Pos())
		end := fset.Position(declNode.End())
		out[key] = &finding{symbol: symbol, pos: fmt.Sprintf("%s:%d", relPath(p.Filename), p.Line)}
		objs[key] = origin(obj)
		spans[key] = append(spans[key], span{file: start.Filename, start: start.Line, end: end.Line})
	}

	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Name == nil || !d.Name.IsExported() {
			// Unexported func — but if it is a METHOD of a candidate type, its
			// receiver mention must not count as a use of that type.
			if d.Recv != nil {
				excludeReceiverSpan(pkg, d, spans)
			}
			return
		}
		if d.Recv != nil {
			recvName := receiverTypeName(d.Recv)
			if recvName == "?" || !ast.IsExported(recvName) {
				// A method on an unexported type is not exported API surface;
				// it is reachable only through interfaces, which the
				// interface exemption handles for exported-type methods.
				excludeReceiverSpan(pkg, d, spans)
				return
			}
			add(d.Name, d, fmt.Sprintf("%s.%s.%s", pkg.PkgPath, recvName, d.Name.Name))
			excludeReceiverSpan(pkg, d, spans)
			return
		}
		add(d.Name, d, fmt.Sprintf("%s.%s", pkg.PkgPath, d.Name.Name))
	case *ast.GenDecl:
		for _, sp := range d.Specs {
			switch s := sp.(type) {
			case *ast.TypeSpec:
				add(s.Name, s, fmt.Sprintf("%s.%s", pkg.PkgPath, s.Name.Name))
			case *ast.ValueSpec:
				for _, name := range s.Names {
					add(name, s, fmt.Sprintf("%s.%s", pkg.PkgPath, name.Name))
				}
			}
		}
	}
}

// excludeReceiverSpan records the receiver type expression of a method as part
// of the receiver type's own definition: a type referenced only by its own
// methods' receivers has no outside caller.
func excludeReceiverSpan(pkg *packages.Package, d *ast.FuncDecl, spans map[objKey][]span) {
	if len(d.Recv.List) == 0 {
		return
	}
	recv := d.Recv.List[0].Type
	ast.Inspect(recv, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if obj := pkg.TypesInfo.Uses[id]; obj != nil {
				if key, ok := keyOf(origin(obj)); ok {
					p := pkg.Fset.Position(id.Pos())
					spans[key] = append(spans[key], span{file: p.Filename, start: p.Line, end: p.Line})
				}
			}
		}
		return true
	})
}

func receiverTypeName(recv *ast.FieldList) string {
	if len(recv.List) == 0 {
		return "?"
	}
	t := recv.List[0].Type
	for {
		switch tt := t.(type) {
		case *ast.StarExpr:
			t = tt.X
		case *ast.IndexExpr:
			t = tt.X
		case *ast.IndexListExpr:
			t = tt.X
		case *ast.Ident:
			return tt.Name
		default:
			return "?"
		}
	}
}

// origin maps generic instantiations back to their declared object.
func origin(obj types.Object) types.Object {
	switch o := obj.(type) {
	case *types.Func:
		return o.Origin()
	case *types.Var:
		return o.Origin()
	}
	return obj
}

// implementsSomeInterface reports whether method fn satisfies a method of any
// interface observed in the load — a concrete method dispatched through an
// interface has no direct reference but is load-bearing.
func implementsSomeInterface(fn *types.Func, interfaces []*types.Interface) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	recv := sig.Recv().Type()
	for _, iface := range interfaces {
		if iface.NumMethods() == 0 {
			continue
		}
		if m := findIfaceMethod(iface, fn.Name()); m == nil {
			continue
		}
		if debugIface {
			fmt.Printf("why-iface: name-match — Implements(recv)=%v Implements(*recv)=%v\n",
				types.Implements(recv, iface), types.Implements(types.NewPointer(recv), iface))
		}
		if types.Implements(recv, iface) || types.Implements(types.NewPointer(recv), iface) {
			return true
		}
	}
	return false
}

func findIfaceMethod(iface *types.Interface, name string) *types.Func {
	for i := 0; i < iface.NumMethods(); i++ {
		if iface.Method(i).Name() == name {
			return iface.Method(i)
		}
	}
	return nil
}

func relPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return p
}

// report applies the allowlist and prints surviving findings. Exit 0 = clean.
func report(inert []finding, allowlistPath string) int {
	allowSymbols, allowPkgs, err := loadAllowlist(allowlistPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deadseams:", err)
		return 2
	}
	matchedSym := map[string]bool{}
	matchedPkg := map[string]bool{}
	var surviving []finding
	for _, f := range inert {
		pkgPath := packageOf(f.symbol)
		switch {
		case allowSymbols[f.symbol] != "":
			matchedSym[f.symbol] = true
		case allowPkgs[pkgPath] != "":
			matchedPkg[pkgPath] = true
		default:
			surviving = append(surviving, f)
		}
	}
	stale := false
	for sym := range allowSymbols {
		if !matchedSym[sym] {
			fmt.Fprintf(os.Stderr, "deadseams: STALE allowlist entry (matches nothing — remove it): symbol %s\n", sym)
			stale = true
		}
	}
	for pkg := range allowPkgs {
		if !matchedPkg[pkg] {
			fmt.Fprintf(os.Stderr, "deadseams: STALE allowlist entry (matches nothing — remove it): package %s\n", pkg)
			stale = true
		}
	}
	if len(surviving) > 0 {
		fmt.Fprintf(os.Stderr, "deadseams: %d exported symbol(s) in internal/ or ee/ with no non-test reference outside their own definition:\n", len(surviving))
		for _, f := range surviving {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", f.symbol, f.pos)
		}
		fmt.Fprintln(os.Stderr, "wire it into a shipping path, delete it with its vocabulary, or allowlist it WITH A REASON in scripts/dead_seams_allowlist.txt")
		return 1
	}
	if stale {
		return 1
	}
	fmt.Println("deadseams: OK (every exported internal/ee symbol has a live reference or a reasoned exemption)")
	return 0
}

// packageOf strips the symbol (and method receiver) segments from a finding
// symbol, leaving the import path.
func packageOf(symbol string) string {
	slash := strings.LastIndex(symbol, "/")
	rest := symbol[slash+1:]
	dot := strings.Index(rest, ".")
	if dot < 0 {
		return symbol
	}
	return symbol[:slash+1] + rest[:dot]
}

// loadAllowlist parses entries of the forms:
//
//	symbol <pkgpath>.<Name>[.<Method>] — <reason>
//	package <pkgpath> — <reason>
//
// A reason is mandatory; the em/double-dash separator keeps it greppable.
func loadAllowlist(path string) (symbols, pkgs map[string]string, err error) {
	symbols, pkgs = map[string]string{}, map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return symbols, pkgs, nil
		}
		return nil, nil, err
	}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var body string
		for _, sep := range []string{"—", "--"} {
			if idx := strings.Index(line, sep); idx >= 0 {
				body = strings.TrimSpace(line[:idx])
				if strings.TrimSpace(line[idx+len(sep):]) == "" {
					return nil, nil, fmt.Errorf("%s:%d: allowlist entry has an empty reason", path, i+1)
				}
				break
			}
		}
		if body == "" {
			return nil, nil, fmt.Errorf("%s:%d: allowlist entry needs '<entry> — <reason>'", path, i+1)
		}
		fields := strings.Fields(body)
		if len(fields) != 2 {
			return nil, nil, fmt.Errorf("%s:%d: expected 'symbol <path>' or 'package <path>'", path, i+1)
		}
		switch fields[0] {
		case "symbol":
			symbols[fields[1]] = line
		case "package":
			pkgs[fields[1]] = line
		default:
			return nil, nil, fmt.Errorf("%s:%d: unknown entry kind %q", path, i+1, fields[0])
		}
	}
	return symbols, pkgs, nil
}

// runSelftest plants both violation shapes through a compiler overlay: an
// exported symbol with no references (must be flagged) and one referenced
// from a planted non-test file (must not be). The analysis under test is the
// same analyze() the live gate runs.
func runSelftest() int {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "deadseams selftest:", err)
		return 2
	}
	dir := filepath.Join(wd, "internal", "opendata")
	overlay := map[string][]byte{
		filepath.Join(dir, "zz_deadseams_planted.go"): []byte(
			"package opendata\n\n// PlantedInertSeam is the selftest's dead symbol.\nfunc PlantedInertSeam() {}\n\n// PlantedUsedSeam is the selftest's live symbol.\nfunc PlantedUsedSeam() {}\n"),
		filepath.Join(dir, "zz_deadseams_planted_use.go"): []byte(
			"package opendata\n\nfunc init() { PlantedUsedSeam() }\n"),
	}
	inert, err := analyzeAll(overlay)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deadseams selftest:", err)
		return 2
	}
	foundInert, foundUsed := false, false
	for _, f := range inert {
		if strings.HasSuffix(f.symbol, ".PlantedInertSeam") {
			foundInert = true
		}
		if strings.HasSuffix(f.symbol, ".PlantedUsedSeam") {
			foundUsed = true
		}
	}
	if !foundInert {
		fmt.Fprintln(os.Stderr, "deadseams SELFTEST FAILED: planted inert symbol was not flagged")
		return 1
	}
	if foundUsed {
		fmt.Fprintln(os.Stderr, "deadseams SELFTEST FAILED: planted USED symbol was wrongly flagged")
		return 1
	}
	fmt.Println("deadseams self-test: OK (planted inert symbol flagged; planted used symbol not flagged)")
	return 0
}
