// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The three licenses LICENSE assigns by tree ("SCOPE OF THIS LICENSE").
const (
	licenseCore       = "BUSL-1.1"
	licenseClient     = "MPL-2.0"
	licenseCommercial = "LicenseRef-Probectl-Commercial"
)

// treeLicense is LICENSE's own rule for a file that carries no license of its
// own: ee/ is commercial, pkg/, proto/ and examples/ are MPL-2.0, everything
// else is the BUSL-1.1 core. path is slash-separated and repository-relative.
func treeLicense(path string) string {
	top, _, _ := strings.Cut(path, "/")
	switch top {
	case "ee":
		return licenseCommercial
	case "pkg", "proto", "examples":
		return licenseClient
	default:
		return licenseCore
	}
}

// licenseOrder ranks the probectl licenses first, in LICENSE's order, so the
// declared expression reads the same way for every artifact.
func licenseOrder(expr string) int {
	switch expr {
	case licenseCore:
		return 0
	case licenseClient:
		return 1
	case licenseCommercial:
		return 2
	default:
		return 3
	}
}

// joinLicenses ANDs the distinct expressions, parenthesising compound ones.
func joinLicenses(exprs map[string]int) string {
	list := make([]string, 0, len(exprs))
	for e := range exprs {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool {
		oi, oj := licenseOrder(list[i]), licenseOrder(list[j])
		if oi != oj {
			return oi < oj
		}
		return list[i] < list[j]
	})
	if len(list) == 1 {
		return list[0]
	}
	parts := make([]string, len(list))
	for i, e := range list {
		if strings.ContainsAny(e, " ()") {
			e = "(" + e + ")"
		}
		parts[i] = e
	}
	return strings.Join(parts, " AND ")
}

var licenseIDPattern = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9.+-]*`)

// licenseIDs returns the license identifiers an SPDX expression names.
func licenseIDs(expr string) []string {
	var ids []string
	for _, tok := range licenseIDPattern.FindAllString(expr, -1) {
		switch tok {
		case "AND", "OR", "WITH":
			continue
		}
		ids = append(ids, tok)
	}
	return ids
}

// sourceTree is the checkout the artifacts were built from plus the
// per-file license map the REUSE gate wrote for it.
type sourceTree struct {
	root   string            // absolute, symlinks resolved
	module string            // the main module path from go.mod
	files  map[string]string // repository-relative path -> SPDX expression
}

type reuseMap struct {
	ReuseToolVersion string            `json:"reuse_tool_version"`
	Files            map[string]string `json:"files"`
}

func newSourceTree(root, mapPath string) (*sourceTree, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return nil, err
	}
	module, err := readModulePath(filepath.Join(abs, "go.mod"))
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("read reuse map: %w", err)
	}
	var m reuseMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse reuse map %s: %w", mapPath, err)
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("reuse map %s lists no files; regenerate it with REUSE_MAP_OUT=<file> scripts/check_reuse_licensing.sh", mapPath)
	}
	return &sourceTree{root: abs, module: module, files: m.Files}, nil
}

// readModulePath returns the module path a go.mod declares.
func readModulePath(goMod string) (string, error) {
	f, err := os.Open(goMod)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s declares no module", goMod)
}

// licenseOf returns a file's license and whether the REUSE map knew it. The
// map covers every file git tracks; anything else is untracked build output.
// A BPF object bpf2go compiled (<dir>/<ident>_<target>.o) carries the license
// of its program, <dir>/bpf/<ident>.bpf.c; any other build output takes its
// tree's license, as LICENSE says every file without its own license does.
func (s *sourceTree) licenseOf(rel string) (string, bool) {
	if expr, ok := s.files[rel]; ok {
		return expr, true
	}
	if strings.HasSuffix(rel, ".o") {
		ident, _, ok := strings.Cut(pathpkg.Base(rel), "_")
		if ok && ident != "" {
			if expr, found := s.files[pathpkg.Join(pathpkg.Dir(rel), "bpf", ident+".bpf.c")]; found {
				return expr, false
			}
		}
	}
	return treeLicense(rel), false
}

// licenseText returns LICENSES/<id>.txt, which the REUSE gate keeps
// byte-identical to LICENSE / ee/LICENSE.
func (s *sourceTree) licenseText(id string) (string, error) {
	if strings.ContainsAny(id, `/\`) {
		return "", fmt.Errorf("invalid license identifier %q", id)
	}
	b, err := os.ReadFile(filepath.Join(s.root, "LICENSES", id+".txt"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("license %s has no LICENSES/%s.txt", id, id)
		}
		return "", err
	}
	return string(b), nil
}

// licenseName is the title line of a license text, for SPDX's name field.
func licenseName(text, fallback string) string {
	line, _, _ := strings.Cut(strings.TrimLeft(text, "\n"), "\n")
	line = string(bytes.TrimSpace([]byte(line)))
	if line == "" {
		return fallback
	}
	return line
}
