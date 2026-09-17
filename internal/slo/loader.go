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
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxDefinitionFileBytes = 1 << 20

// LoadDir parses every *.yaml/*.yml in dir (each file may hold multiple
// YAML documents separated by ---). dir "" loads nothing (the engine runs
// with zero SLOs and the API says so honestly).
// LoadDir loads every OpenSLO document under dir. requireTenant (the
// multi-tenant and regulated profiles) refuses a definition without
// metadata.labels.tenant: a deployment-wide definition would feed on every
// tenant's results and show up in every tenant's SLO list (DPR-068).
func LoadDir(dir string, requireTenant bool) ([]SLO, error) {
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
		raw, err := readDefinitionFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("slo: read %s: %w", name, err)
		}
		for _, doc := range splitDocs(string(raw)) {
			s, err := Parse([]byte(doc))
			if err != nil {
				return nil, fmt.Errorf("slo: %s: %w", name, err)
			}
			if requireTenant && s.TenantID == "" {
				return nil, fmt.Errorf("slo: %s: %q has no metadata.labels.tenant — every definition must belong to one tenant in the multi-tenant and regulated profiles (DPR-068)", name, s.Name)
			}
			key := s.TenantID + "/" + s.Name
			if seen[key] {
				return nil, fmt.Errorf("slo: duplicate SLO name %q (file %s)", s.Name, name)
			}
			seen[key] = true
			out = append(out, s)
		}
	}
	return out, nil
}

func readDefinitionFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxDefinitionFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > maxDefinitionFileBytes {
		return nil, fmt.Errorf("definition exceeds %d-byte limit", maxDefinitionFileBytes)
	}
	return raw, nil
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
