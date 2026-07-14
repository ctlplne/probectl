// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package slo

// Loading: OpenSLO YAML files from an operator directory. A missing or
// malformed directory/file FAILS startup (the operator believes their SLOs
// are tracked; silently dropping one is worse than refusing to boot).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadDir parses every *.yaml/*.yml in dir (each file may hold multiple
// YAML documents separated by ---). dir "" loads nothing (the engine runs
// with zero SLOs and the API says so honestly).
func LoadDir(dir string) ([]SLO, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("slo: definitions dir: %w", err)
	}
	var out []SLO
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("slo: read %s: %w", name, err)
		}
		for _, doc := range splitDocs(string(raw)) {
			s, err := Parse([]byte(doc))
			if err != nil {
				return nil, fmt.Errorf("slo: %s: %w", name, err)
			}
			if seen[s.Name] {
				return nil, fmt.Errorf("slo: duplicate SLO name %q (file %s)", s.Name, name)
			}
			seen[s.Name] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// splitDocs splits a multi-document YAML stream on top-level "---" lines.
func splitDocs(raw string) []string {
	var docs []string
	for _, d := range strings.Split(raw, "\n---") {
		if strings.TrimSpace(d) != "" {
			docs = append(docs, d)
		}
	}
	return docs
}
