// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPRDDiligenceRegisterCoversEveryReferencedFinding(t *testing.T) {
	prd := readPRDv1(t)
	registerPath := "diligence-register.md"
	registerBytes, err := os.ReadFile(registerPath)
	if err != nil {
		t.Fatalf("read committed diligence replacement %s: %v", registerPath, err)
	}
	register := string(registerBytes)

	for _, stale := range []string{
		"probectl-audit/",
		"docs/audit/",
	} {
		if strings.Contains(prd, stale) {
			t.Errorf("probectl-PRD-v1.0.md still points at missing diligence target %q", stale)
		}
	}
	for _, want := range []string{
		"docs/diligence-register.md",
		"docs/audit.md",
	} {
		if !strings.Contains(prd, want) {
			t.Errorf("probectl-PRD-v1.0.md must link committed diligence target %q", want)
		}
	}

	findingRE := regexp.MustCompile(`U-[0-9]{3}`)
	prdFindings := make(map[string]struct{})
	for _, finding := range findingRE.FindAllString(prd, -1) {
		prdFindings[finding] = struct{}{}
	}
	if len(prdFindings) == 0 {
		t.Fatal("probectl-PRD-v1.0.md has no diligence finding labels to verify")
	}

	rowRE := regexp.MustCompile(`(?m)^\| (U-[0-9]{3}) \|`)
	registerCounts := make(map[string]int)
	for _, match := range rowRE.FindAllStringSubmatch(register, -1) {
		registerCounts[match[1]]++
	}
	for finding := range prdFindings {
		if got := registerCounts[finding]; got != 1 {
			t.Errorf("diligence finding %s has %d register rows; want exactly 1", finding, got)
		}
	}
	for finding := range registerCounts {
		if _, cited := prdFindings[finding]; !cited {
			t.Errorf("diligence register carries uncited finding %s; keep this replacement scoped to the PRD contract", finding)
		}
	}

	linkRE := regexp.MustCompile(`\[[^]]+\]\(([^)]+)\)`)
	for _, match := range linkRE.FindAllStringSubmatch(register, -1) {
		target := match[1]
		if strings.Contains(target, "://") || strings.HasPrefix(target, "#") {
			continue
		}
		if i := strings.IndexByte(target, '#'); i >= 0 {
			target = target[:i]
		}
		if target == "" {
			continue
		}
		resolved := filepath.Clean(filepath.Join(filepath.Dir(registerPath), filepath.FromSlash(target)))
		if _, err := os.Stat(resolved); err != nil {
			t.Errorf("diligence register link %q resolves to missing target %q: %v", match[1], resolved, err)
		}
	}
}
