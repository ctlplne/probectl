// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	noAssertion = "NOASSERTION"
	toolCreator = "Tool: probectl-sbom-license"
	// syft's sourceInfo for a Go binary's module: "<prefix>: <path>".
	goBinarySourceInfo = "acquired package info from go module information: "
)

// spdxDoc keeps every field as raw JSON so a rewrite preserves what it does
// not touch; only package licenseDeclared, the extracted-license table and
// the creator list are ever changed.
type spdxDoc struct {
	top      map[string]json.RawMessage
	packages []map[string]json.RawMessage
}

func readSBOM(path string) (*spdxDoc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseSBOM(raw)
}

func parseSBOM(raw []byte) (*spdxDoc, error) {
	d := &spdxDoc{}
	if err := json.Unmarshal(raw, &d.top); err != nil {
		return nil, fmt.Errorf("parse SPDX JSON: %w", err)
	}
	var version string
	if err := json.Unmarshal(d.top["spdxVersion"], &version); err != nil || !strings.HasPrefix(version, "SPDX-2.") {
		return nil, fmt.Errorf("not an SPDX 2.x JSON document (spdxVersion %q)", version)
	}
	if pk, ok := d.top["packages"]; ok {
		if err := json.Unmarshal(pk, &d.packages); err != nil {
			return nil, fmt.Errorf("parse SPDX packages: %w", err)
		}
	}
	return d, nil
}

func (d *spdxDoc) marshal() ([]byte, error) {
	pk, err := encode(d.packages)
	if err != nil {
		return nil, err
	}
	d.top["packages"] = pk
	return encode(d.top)
}

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func writeSBOM(path string, d *spdxDoc) error {
	b, err := d.marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func str(m map[string]json.RawMessage, key string) string {
	var s string
	if raw, ok := m[key]; ok {
		_ = json.Unmarshal(raw, &s) // a non-string value reads as ""
	}
	return s
}

func setStr(m map[string]json.RawMessage, key, value string) {
	b, _ := json.Marshal(value) // marshaling a string cannot fail
	m[key] = b
}

// purl returns a package's package-URL external reference, if any.
func purl(p map[string]json.RawMessage) string {
	var refs []struct {
		ReferenceType    string `json:"referenceType"`
		ReferenceLocator string `json:"referenceLocator"`
	}
	if raw, ok := p["externalRefs"]; ok {
		_ = json.Unmarshal(raw, &refs) // a malformed list reads as empty
	}
	for _, r := range refs {
		if r.ReferenceType == "purl" {
			return r.ReferenceLocator
		}
	}
	return ""
}

// isFirstPartyGo reports whether a package is the probectl main module as
// syft found it in a Go binary.
func isFirstPartyGo(p map[string]json.RawMessage, module string) bool {
	u := purl(p)
	base, _, _ := strings.Cut(u, "@")
	base, _, _ = strings.Cut(base, "?")
	return str(p, "name") == module && base == "pkg:golang/"+module
}

// isFirstPartyOther reports whether a package is probectl's own npm or PyPI
// package (e.g. probectl-browser-worker). Those declare their license in
// their own manifest, which syft reads; check() holds them to it.
func isFirstPartyOther(p map[string]json.RawMessage) bool {
	u := purl(p)
	return strings.HasPrefix(u, "pkg:npm/probectl-") || strings.HasPrefix(u, "pkg:pypi/probectl-")
}

func undeclared(expr string) bool {
	return expr == "" || expr == noAssertion || expr == "NONE"
}

// goBinaryPath is the binary a Go package came from, as syft's sourceInfo
// names it (relative to the scanned directory or image root).
func goBinaryPath(p map[string]json.RawMessage) (string, error) {
	info := str(p, "sourceInfo")
	path, ok := strings.CutPrefix(info, goBinarySourceInfo)
	if !ok || path == "" || strings.Contains(path, ", ") {
		return "", fmt.Errorf("package %s: sourceInfo %q does not name exactly one Go binary", str(p, "SPDXID"), info)
	}
	return path, nil
}

// firstPartyBinaries lists the artifact path of every first-party Go package.
func firstPartyBinaries(d *spdxDoc, module string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range d.packages {
		if !isFirstPartyGo(p, module) {
			continue
		}
		path, err := goBinaryPath(p)
		if err != nil {
			return nil, err
		}
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("the SBOM has no %s package from a Go binary", module)
	}
	return out, nil
}

type linker interface {
	files(ctx context.Context, artifact string, warn io.Writer) ([]linkedFile, error)
}

// annotate sets licenseDeclared on every first-party Go package from the
// licenses of the files its binary links, and defines any LicenseRef it uses.
func annotate(d *spdxDoc, src *sourceTree, l linker) ([]string, error) {
	ctx := context.Background()
	var report []string
	used := map[string]bool{}
	cache := map[string]string{}
	found := 0
	for _, p := range d.packages {
		if !isFirstPartyGo(p, src.module) {
			continue
		}
		found++
		artifact, err := goBinaryPath(p)
		if err != nil {
			return nil, err
		}
		expr, ok := cache[artifact]
		if !ok {
			var warn strings.Builder
			files, err := l.files(ctx, artifact, &warn)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", artifact, err)
			}
			counts := map[string]int{}
			untracked := 0
			for _, f := range files {
				lic, known := src.licenseOf(f.rel)
				if !known {
					untracked++
				}
				counts[lic]++
			}
			expr = joinLicenses(counts)
			cache[artifact] = expr
			report = append(report, summarize(artifact, len(files), untracked, counts, expr))
			if warn.Len() > 0 {
				report = append(report, strings.Split(strings.TrimRight(warn.String(), "\n"), "\n")...)
			}
		}
		setStr(p, "licenseDeclared", expr)
		for _, id := range licenseIDs(expr) {
			used[id] = true
		}
	}
	if found == 0 {
		return nil, fmt.Errorf("the SBOM has no %s package from a Go binary; nothing to declare", src.module)
	}
	if err := defineLicenseRefs(d, src, used); err != nil {
		return nil, err
	}
	addCreator(d)
	return report, nil
}

func summarize(artifact string, n, untracked int, counts map[string]int, expr string) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if licenseOrder(keys[i]) != licenseOrder(keys[j]) {
			return licenseOrder(keys[i]) < licenseOrder(keys[j])
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, counts[k])
	}
	return fmt.Sprintf("%s: licenseDeclared %q from %d linked first-party files (%s; %d untracked build output by tree)",
		artifact, expr, n, strings.Join(parts, ", "), untracked)
}

type extractedLicense struct {
	LicenseID     string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
	Name          string `json:"name,omitempty"`
}

// defineLicenseRefs adds every used LicenseRef to hasExtractedLicensingInfos
// with its LICENSES/ text; SPDX 2.3 requires a LicenseRef to be defined in
// the document that uses it.
func defineLicenseRefs(d *spdxDoc, src *sourceTree, used map[string]bool) error {
	var have []json.RawMessage
	if raw, ok := d.top["hasExtractedLicensingInfos"]; ok {
		if err := json.Unmarshal(raw, &have); err != nil {
			return fmt.Errorf("parse hasExtractedLicensingInfos: %w", err)
		}
	}
	defined := map[string]bool{}
	for _, raw := range have {
		var e extractedLicense
		if err := json.Unmarshal(raw, &e); err == nil {
			defined[e.LicenseID] = true
		}
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	added := false
	for _, id := range ids {
		if !strings.HasPrefix(id, "LicenseRef-") || defined[id] {
			continue
		}
		text, err := src.licenseText(id)
		if err != nil {
			return err
		}
		raw, err := encode(extractedLicense{LicenseID: id, ExtractedText: text, Name: licenseName(text, id)})
		if err != nil {
			return err
		}
		have = append(have, raw)
		added = true
	}
	if added {
		raw, err := encode(have)
		if err != nil {
			return err
		}
		d.top["hasExtractedLicensingInfos"] = raw
	}
	return nil
}

func addCreator(d *spdxDoc) {
	var ci map[string]json.RawMessage
	if err := json.Unmarshal(d.top["creationInfo"], &ci); err != nil || ci == nil {
		return
	}
	var creators []string
	_ = json.Unmarshal(ci["creators"], &creators) // absent reads as empty
	for _, c := range creators {
		if c == toolCreator {
			return
		}
	}
	creators = append(creators, toolCreator)
	if b, err := encode(creators); err == nil {
		ci["creators"] = b
	}
	if b, err := encode(ci); err == nil {
		d.top["creationInfo"] = b
	}
}

// check reports every first-party package that still declares no license
// and every LicenseRef the document uses without defining it.
func check(d *spdxDoc) (lines, problems []string) {
	defined := map[string]bool{}
	var have []extractedLicense
	if raw, ok := d.top["hasExtractedLicensingInfos"]; ok {
		if err := json.Unmarshal(raw, &have); err != nil {
			problems = append(problems, "hasExtractedLicensingInfos is malformed: "+err.Error())
		}
	}
	for _, e := range have {
		if e.ExtractedText != "" {
			defined[e.LicenseID] = true
		}
	}
	goPkgs := 0
	for _, p := range d.packages {
		if !isFirstPartyGoAny(p) && !isFirstPartyOther(p) {
			continue
		}
		if isFirstPartyGoAny(p) {
			goPkgs++
		}
		expr := str(p, "licenseDeclared")
		lines = append(lines, fmt.Sprintf("%s (%s): licenseDeclared %s", str(p, "name"), strings.TrimPrefix(str(p, "sourceInfo"), goBinarySourceInfo), expr))
		if undeclared(expr) {
			problems = append(problems, fmt.Sprintf("first-party package %s (%s) declares %q; run probectl-sbom-license annotate", str(p, "name"), str(p, "SPDXID"), expr))
			continue
		}
		for _, id := range licenseIDs(expr) {
			if strings.HasPrefix(id, "LicenseRef-") && !defined[id] {
				problems = append(problems, fmt.Sprintf("first-party package %s uses %s but the document does not define it in hasExtractedLicensingInfos", str(p, "name"), id))
			}
		}
	}
	if goPkgs == 0 {
		problems = append(problems, "no first-party Go package (pkg:golang/github.com/ctlplne/probectl) in the SBOM")
	}
	return lines, problems
}

// isFirstPartyGoAny matches the probectl main module without a checkout, for
// check(): the module path is fixed by go.mod and the purl syft writes.
func isFirstPartyGoAny(p map[string]json.RawMessage) bool {
	return isFirstPartyGo(p, firstPartyModule)
}

// firstPartyModule is the module path in go.mod. annotate reads it from the
// checkout; check and binaries, which may run without one, use this constant,
// and TestFirstPartyModuleMatchesGoMod keeps the two equal.
const firstPartyModule = "github.com/ctlplne/probectl"
