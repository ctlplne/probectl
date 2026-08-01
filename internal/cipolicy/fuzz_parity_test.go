// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// The fuzz attack-surface parity gate (Foundation-Loop S-7f81b4c2).
//
// The pre-existing fuzz policy gate proves every DISCOVERED target is run and
// that the nightly budget fits the job timeout. It is blind to the failure that
// matters more: a parser with no target at all. SNMP traps, syslog, BMP framing
// and AS_PATH, and WiFi text parsing were all untrusted input with no fuzz
// target — and they were the parsers with the weakest bounds discipline.
//
// This gate closes that gap with a rule, not a list: in the ingest-surface
// packages, every function that CONSUMES untrusted input (a parse/decode/read
// entry taking []byte or a raw text payload) must appear in
// docs/fuzz/parser_register.json bound either to a fuzz target that exists, or
// to a written exemption. A new parser is a build failure until someone
// decides which of those it is.
package cipolicy

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fuzzSurfacePackages take bytes (or raw vendor text) off the network, off a
// listener, or out of a device tool — the untrusted-input surface.
var fuzzSurfacePackages = []string{
	"../flow", "../bgp", "../device", "../siem", "../endpoint",
	"../otel/otlp", "../path", "../rum", "../notify", "../change",
}

// parserRegister is docs/fuzz/parser_register.json: parser key → binding.
type parserRegister struct {
	Purpose string                  `json:"purpose"`
	Parsers map[string]parserTarget `json:"parsers"`
}

type parserTarget struct {
	// Target is the FuzzXxx function that exercises this parser (in the same
	// package unless Package says otherwise). Empty requires Exempt.
	Target string `json:"target,omitempty"`
	// Exempt records why a discovered function is NOT an untrusted-input
	// parser (a helper over already-validated values, a formatter, …).
	Exempt string `json:"exempt,omitempty"`
}

// discoverParsers returns "pkg.Func" for every function in dir that looks like
// an untrusted-input entry: its name begins with parse/decode/read (any case)
// and it takes a []byte or a string parameter carrying a raw payload.
func discoverParsers(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkg := strings.TrimPrefix(filepath.ToSlash(dir), "../")
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !parserName(fn.Name.Name) {
				continue
			}
			if !takesRawPayload(fn) {
				continue
			}
			out = append(out, pkg+"."+receiverPrefix(fn)+fn.Name.Name)
		}
	}
	sort.Strings(out)
	return out
}

// receiverPrefix disambiguates same-named methods on different receivers
// (two decoders both named decode, one per protocol).
func receiverPrefix(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "."
	}
	return ""
}

func parserName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"parse", "decode", "read"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// takesRawPayload reports whether fn accepts bytes or a raw text payload.
func takesRawPayload(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		if isByteSlice(field.Type) {
			return true
		}
		if id, ok := field.Type.(*ast.Ident); ok && id.Name == "string" {
			// Only names that read as a payload, not a key/name/id argument.
			for _, n := range field.Names {
				switch strings.ToLower(n.Name) {
				case "text", "body", "raw", "line", "payload", "out", "s", "rest", "v":
					return true
				}
			}
		}
	}
	return false
}

// fuzzTargets returns every FuzzXxx function name declared in dir's tests.
func fuzzTargets(t *testing.T, dir string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(fn.Name.Name, "Fuzz") {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

func loadParserRegister(t *testing.T) parserRegister {
	t.Helper()
	raw, err := os.ReadFile("../../docs/fuzz/parser_register.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg parserRegister
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestFuzzParityEveryParserIsRegistered(t *testing.T) {
	reg := loadParserRegister(t)
	seen := map[string]bool{}
	var unregistered, danglingTarget []string

	for _, dir := range fuzzSurfacePackages {
		targets := fuzzTargets(t, dir)
		for _, key := range discoverParsers(t, dir) {
			seen[key] = true
			binding, ok := reg.Parsers[key]
			if !ok {
				unregistered = append(unregistered, key)
				continue
			}
			if binding.Target == "" {
				if strings.TrimSpace(binding.Exempt) == "" {
					unregistered = append(unregistered, key+" (register entry has neither target nor exemption reason)")
				}
				continue
			}
			if !targets[binding.Target] {
				danglingTarget = append(danglingTarget, key+" → "+binding.Target+" (no such fuzz target in the package)")
			}
		}
	}
	if len(unregistered) > 0 {
		t.Errorf("parsers of untrusted input with no entry in docs/fuzz/parser_register.json:\n  %s\nbind each to a fuzz target, or record why it is not an untrusted-input parser",
			strings.Join(unregistered, "\n  "))
	}
	if len(danglingTarget) > 0 {
		t.Errorf("register entries naming a fuzz target that does not exist:\n  %s", strings.Join(danglingTarget, "\n  "))
	}

	// A register entry that no longer matches a discovered parser is stale —
	// the same anti-rot rule the dead-seams allowlist carries.
	var stale []string
	for key := range reg.Parsers {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("stale register entries (they match no discovered parser — remove them):\n  %s", strings.Join(stale, "\n  "))
	}
}

// TestFuzzParityCoversTheNamedGaps pins the four surfaces the assessment
// called out, so a future refactor cannot quietly drop their targets.
func TestFuzzParityCoversTheNamedGaps(t *testing.T) {
	for dir, want := range map[string][]string{
		"../bgp":      {"FuzzBMPFraming", "FuzzBMPRouteMonitoring", "FuzzBGPASPath"},
		"../siem":     {"FuzzParseSyslog"},
		"../device":   {"FuzzSNMPTrapDatagram"},
		"../endpoint": {"FuzzWiFiParsers"},
	} {
		targets := fuzzTargets(t, dir)
		for _, name := range want {
			if !targets[name] {
				t.Errorf("%s: fuzz target %s is missing (it covers a surface the assessment named)", dir, name)
			}
		}
	}
}

func TestFuzzParitySelfTestCatchesAnUnregisteredParser(t *testing.T) {
	fset := token.NewFileSet()
	planted, err := parser.ParseFile(fset, "planted.go", `package bgp

// An untrusted-input parser with no fuzz target — the shape this gate exists
// to catch.
func parseVendorExtension(raw []byte) error { return nil }

// A raw text payload counts too.
func decodeVendorText(text string) error { return nil }

// NOT a parser of untrusted input: no payload parameter.
func parseTimeout(seconds int) error { return nil }

// Not a parse/decode/read entry at all.
func formatVendor(raw []byte) string { return "" }
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, decl := range planted.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !parserName(fn.Name.Name) || !takesRawPayload(fn) {
			continue
		}
		found = append(found, fn.Name.Name)
	}
	sort.Strings(found)
	want := []string{"decodeVendorText", "parseVendorExtension"}
	if strings.Join(found, ",") != strings.Join(want, ",") {
		t.Fatalf("planted-parser discovery = %v, want %v", found, want)
	}

	// And an entry naming a target that does not exist must be detectable.
	targets := map[string]bool{"FuzzRealOne": true}
	if targets["FuzzGhost"] {
		t.Fatal("ghost target must not resolve")
	}
}
